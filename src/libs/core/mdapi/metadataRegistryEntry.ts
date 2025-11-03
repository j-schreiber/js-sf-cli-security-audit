import { PathLike, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { XMLParser } from 'fast-xml-parser';
import { ComponentSet, FileResponse, RetrieveResult } from '@salesforce/source-deploy-retrieve';
import { Connection } from '@salesforce/core';
import { RETRIEVE_CACHE } from '../constants.js';

export type MetadataRegistryEntryOpts<Type, Key extends keyof Type> = {
  /**
   * Metadata API name of the type.
   */
  retrieveType: string;
  /**
   * Metadata API name entity.
   */
  retrieveName?: string;
  /**
   * Optional XML parser instance. Typically used to fix errors for
   * properties that must be parsed as list.
   */
  parser?: XMLParser;
  /**
   * Name of the root node in XML file content
   */
  rootNodeName: Key;
  /**
   * Post processor function that sanitises the XML parse result
   */
  parsePostProcessor?: (parseResult: Type[Key]) => Type[Key];
};

export type NamedMetadataResolver<Type> = {
  resolve(con: Connection, componentNames: string[]): Promise<Record<string, Type>>;
};

export default abstract class MetadataRegistryEntry<Type, Key extends keyof Type> {
  public parser: XMLParser;
  public retrieveType: string;
  public rootNodeName: Key;

  public constructor(private opts: MetadataRegistryEntryOpts<Type, Key>) {
    this.retrieveType = this.opts.retrieveType;
    this.parser = this.opts.parser ?? new XMLParser();
    this.rootNodeName = this.opts.rootNodeName;
  }

  public parse(fullFilePath: PathLike): Type[Key] {
    const fileContent = readFileSync(fullFilePath, 'utf-8');
    const parsedContent = this.parser.parse(fileContent) as Type;
    if (this.opts.parsePostProcessor) {
      return this.opts.parsePostProcessor(parsedContent[this.rootNodeName]);
    }
    return parsedContent[this.rootNodeName];
  }
}

export async function retrieve(compSet: ComponentSet, con: Connection): Promise<RetrieveResult> {
  const retrieveRequest = await compSet.retrieve({
    usernameOrConnection: con,
    output: RETRIEVE_CACHE,
  });
  const retrieveResult = await retrieveRequest.pollStatus();
  return retrieveResult;
}

export function cleanRetrieveDir(files: FileResponse[]): void {
  const dirNames = new Set<string>();
  files.forEach((file) => {
    if (file.filePath) {
      const dirName = path.dirname(path.normalize(file.filePath));
      const parts = dirName.split(path.sep).filter((dirPart) => dirPart.startsWith('metadataPackage_'));
      parts.forEach((mdPart) => dirNames.add(mdPart));
    }
  });
  dirNames.forEach((dir) => {
    rmSync(path.join(RETRIEVE_CACHE, dir), { recursive: true });
  });
}
