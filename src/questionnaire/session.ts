import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import { QuestionnaireSession } from '../schema/index.js';
import type {
  APPPrinciple,
  AttestLensFinding,
  QuestionnairePrincipleResult,
  QuestionnaireResponse,
  QuestionnaireSession as QuestionnaireSessionType,
} from '../schema/index.js';

export type SessionTarget =
  | { kind: 'path'; name: string; path: string; url?: undefined }
  | { kind: 'url'; name: string; url: string; path?: undefined };

export interface SessionPaths {
  directory: string;
  sessionPath: string;
  scanSnapshotPath: string;
}

function slugifyTarget(targetName: string): string {
  return targetName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'target';
}

export function buildSessionPaths(outputDir: string, targetName: string, sessionId: string): SessionPaths {
  const directory = path.join(path.resolve(outputDir), 'attest', slugifyTarget(targetName), sessionId);
  return {
    directory,
    sessionPath: path.join(directory, 'session.json'),
    scanSnapshotPath: path.join(directory, 'scan-results.json'),
  };
}

export function buildFindingsHash(findings: AttestLensFinding[]): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(findings.map((finding) => finding.id).sort()))
    .digest('hex')
    .substring(0, 32);
}

export function createQuestionnaireSession(params: {
  id?: string;
  target: SessionTarget;
  strictMode: boolean;
  scanSnapshotPath: string;
  findingsHash: string;
  principleResults: QuestionnairePrincipleResult[];
  currentQuestionId?: string;
}): QuestionnaireSessionType {
  const now = new Date().toISOString();
  return {
    id: params.id || crypto.randomUUID(),
    version: '1.0',
    status: 'in_progress',
    target: params.target,
    startedAt: now,
    updatedAt: now,
    strictMode: params.strictMode,
    scanSnapshotPath: params.scanSnapshotPath,
    findingsHash: params.findingsHash,
    answers: [],
    principleResults: params.principleResults,
    currentQuestionId: params.currentQuestionId,
  };
}

export async function ensureSessionDirectory(paths: SessionPaths): Promise<void> {
  await fs.mkdir(paths.directory, { recursive: true });
}

export async function saveQuestionnaireSession(session: QuestionnaireSessionType, sessionPath: string): Promise<void> {
  const normalizedSession = QuestionnaireSession.parse({
    ...session,
    updatedAt: new Date().toISOString(),
  });
  await fs.writeFile(sessionPath, JSON.stringify(normalizedSession, null, 2));
}

export async function loadQuestionnaireSession(sessionPath: string): Promise<QuestionnaireSessionType> {
  const raw = JSON.parse(await fs.readFile(path.resolve(sessionPath), 'utf-8'));
  return QuestionnaireSession.parse(raw);
}

export async function writeScanSnapshot(snapshotPath: string, payload: unknown): Promise<void> {
  await fs.writeFile(snapshotPath, JSON.stringify(payload, null, 2));
}

export async function loadScanSnapshot<T>(snapshotPath: string): Promise<T> {
  return JSON.parse(await fs.readFile(path.resolve(snapshotPath), 'utf-8')) as T;
}

export function updateSessionProgress(
  session: QuestionnaireSessionType,
  answers: QuestionnaireResponse[],
  principleResults: QuestionnairePrincipleResult[],
  currentQuestionId?: string,
): QuestionnaireSessionType {
  return {
    ...session,
    answers,
    principleResults,
    currentQuestionId,
    updatedAt: new Date().toISOString(),
  };
}

export function completeQuestionnaireSession(
  session: QuestionnaireSessionType,
  answers: QuestionnaireResponse[],
  principleResults: QuestionnairePrincipleResult[],
): QuestionnaireSessionType {
  const now = new Date().toISOString();
  return {
    ...session,
    status: 'completed',
    answers,
    principleResults,
    currentQuestionId: undefined,
    updatedAt: now,
    completedAt: now,
  };
}
