import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { mapFindingToAPP } from '../mapping/engine.js';
import { IacAdapter } from './iac.js';

describe('IacAdapter', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'attestlens-iac-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('detects conservative Dockerfile and Terraform misconfigurations', async () => {
    await writePositiveFixture(tempDir);

    const result = await new IacAdapter().scan(tempDir);
    const ruleIds = new Set(result.findings.map(finding => finding.sourceRule));

    for (let index = 1; index <= 25; index += 1) {
      expect(ruleIds.has(`VS-IAC-${String(index).padStart(3, '0')}`)).toBe(true);
    }
    expect(result.errors).toHaveLength(0);
  });

  it('does not emit findings for hardened Dockerfile and Terraform fixtures', async () => {
    await writeNegativeFixture(tempDir);

    const result = await new IacAdapter().scan(tempDir);

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it('gracefully skips projects without Dockerfile or Terraform files', async () => {
    await fs.writeFile(path.join(tempDir, 'README.md'), '# no iac here\n');

    const result = await new IacAdapter().scan(tempDir);

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it('maps IaC findings to APP/NDB obligations', async () => {
    await writePositiveFixture(tempDir);

    const result = await new IacAdapter().scan(tempDir);
    const secret = result.findings.find(finding => finding.sourceRule === 'VS-IAC-005');
    const publicBucket = result.findings.find(finding => finding.sourceRule === 'VS-IAC-017');

    expect(secret).toBeDefined();
    expect(publicBucket).toBeDefined();
    expect(secret!.code).not.toContain('sk_live');
    expect(mapFindingToAPP(secret!).map(mapping => mapping.principle)).toEqual(['APP_11', 'NDB']);
    expect(mapFindingToAPP(publicBucket!).map(mapping => mapping.principle)).toEqual(['APP_11', 'APP_8']);
  });
});

async function writePositiveFixture(projectDir: string): Promise<void> {
  await fs.writeFile(
    path.join(projectDir, 'Dockerfile'),
    [
      'FROM node:latest',
      'ARG API_TOKEN="sk_live_1234567890abcdef"',
      'ENV DB_PASSWORD="supersecretvalue123"',
      'ADD https://example.com/app.tar.gz /app/',
      'COPY *.js /app/',
      'RUN apt-get update && apt-get install -y curl',
      'RUN sudo chmod 777 /app/data',
      'RUN echo "10.0.1.25"',
      'EXPOSE 80 5432',
      'CMD ["node", "server.js"]',
    ].join('\n'),
  );
  await fs.writeFile(
    path.join(projectDir, 'root.Dockerfile'),
    [
      'FROM node:20.11.1',
      'USER root',
      'HEALTHCHECK CMD node healthcheck.js',
      'CMD ["node", "server.js"]',
    ].join('\n'),
  );
  await fs.writeFile(
    path.join(projectDir, 'main.tf'),
    [
      'provider "aws" {}',
      '',
      'resource "aws_s3_bucket" "public_data" {',
      '  bucket = "public-data"',
      '  acl = "public-read"',
      '}',
      '',
      'resource "aws_db_instance" "db" {',
      '  allocated_storage = 20',
      '  engine = "postgres"',
      '}',
      '',
      'resource "aws_security_group" "open" {',
      '  ingress {',
      '    from_port = 443',
      '    to_port = 443',
      '    protocol = "tcp"',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '}',
      '',
      'resource "aws_iam_policy" "admin" {',
      '  policy = jsonencode({ Statement = [{ Action = "*", Resource = "*" }] })',
      '}',
      '',
      'resource "aws_ebs_volume" "data" {',
      '  availability_zone = "ap-southeast-2a"',
      '  size = 10',
      '}',
      '',
      'resource "aws_lambda_function" "worker" {',
      '  filename = "worker.zip"',
      '  function_name = "worker"',
      '  role = aws_iam_role.role.arn',
      '  handler = "index.handler"',
      '  runtime = "nodejs20.x"',
      '}',
      '',
      'variable "db_password" {',
      '  default = "supersecretvalue123"',
      '}',
    ].join('\n'),
  );
}

async function writeNegativeFixture(projectDir: string): Promise<void> {
  await fs.writeFile(path.join(projectDir, '.dockerignore'), 'node_modules\n.env\n');
  await fs.writeFile(
    path.join(projectDir, 'Dockerfile'),
    [
      'FROM node:20.11.1',
      'RUN apt-get update && apt-get install --no-install-recommends -y curl && rm -rf /var/lib/apt/lists/*',
      'COPY package.json /app/package.json',
      'USER node',
      'HEALTHCHECK CMD node healthcheck.js',
      'EXPOSE 3000',
      'CMD ["node", "server.js"]',
    ].join('\n'),
  );
  await fs.writeFile(
    path.join(projectDir, 'main.tf'),
    [
      'terraform {',
      '  required_providers {',
      '    aws = {',
      '      source = "hashicorp/aws"',
      '      version = "~> 5.0"',
      '    }',
      '  }',
      '}',
      '',
      'resource "aws_s3_bucket" "private" {',
      '  bucket = "private-data"',
      '}',
      '',
      'resource "aws_s3_bucket_server_side_encryption_configuration" "private" {',
      '  bucket = aws_s3_bucket.private.id',
      '  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }',
      '}',
      '',
      'resource "aws_s3_bucket_logging" "private" {',
      '  bucket = aws_s3_bucket.private.id',
      '  target_bucket = aws_s3_bucket.private.id',
      '  target_prefix = "logs/"',
      '}',
      '',
      'resource "aws_db_instance" "db" {',
      '  storage_encrypted = true',
      '}',
      '',
      'resource "aws_security_group" "private" {',
      '  ingress { cidr_blocks = ["10.0.0.0/8"] }',
      '}',
      '',
      'resource "aws_iam_policy" "limited" {',
      '  policy = jsonencode({ Statement = [{ Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::bucket/*"] }] })',
      '}',
      '',
      'resource "aws_ebs_volume" "data" {',
      '  encrypted = true',
      '}',
      '',
      'resource "aws_lambda_function" "worker" {',
      '  filename = "worker.zip"',
      '  function_name = "worker"',
      '  role = aws_iam_role.role.arn',
      '  handler = "index.handler"',
      '  runtime = "nodejs20.x"',
      '  vpc_config { subnet_ids = ["subnet-123"] security_group_ids = ["sg-123"] }',
      '}',
      '',
      'variable "db_password" {',
      '  type = string',
      '  sensitive = true',
      '}',
    ].join('\n'),
  );
}
