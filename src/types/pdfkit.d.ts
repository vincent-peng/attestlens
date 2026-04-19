declare module 'pdfkit' {
  import { Readable, Writable } from 'node:stream';

  export interface DocumentInformation {
    Title?: string;
    Author?: string;
    Subject?: string;
    Keywords?: string;
    Creator?: string;
    Producer?: string;
    CreationDate?: Date;
    ModDate?: Date;
  }

  export interface PDFDocumentOptions {
    size?: string | [number, number];
    margin?: number;
    info?: DocumentInformation;
  }

  export interface TextOptions {
    continued?: boolean;
    width?: number;
    align?: 'left' | 'center' | 'right' | 'justify';
  }

  export default class PDFDocument extends Readable {
    constructor(options?: PDFDocumentOptions);
    pipe<T extends Writable>(destination: T): T;
    addPage(options?: PDFDocumentOptions): this;
    end(): void;
    font(name: string): this;
    fontSize(size: number): this;
    fillColor(color: string): this;
    moveDown(lines?: number): this;
    text(text: string, options?: TextOptions): this;
    text(text: string, x: number, y: number, options?: TextOptions): this;
    on(event: 'error', listener: (error: Error) => void): this;
  }
}
