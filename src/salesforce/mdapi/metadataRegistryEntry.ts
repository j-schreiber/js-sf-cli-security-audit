import fs from 'node:fs';
import path from 'node:path';
import { XMLParser } from 'fast-xml-parser';
import { ComponentSet, RetrieveResult } from '@salesforce/source-deploy-retrieve';
import { Connection } from '@salesforce/core';
import { RETRIEVE_CACHE } from './constants.js';

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

export type ComponentRetrieveResult = {
  packageName: string;
  retrievePath: string;
  mdapiRetrieveResult: RetrieveResult;
  retrievedComponents: MdapiComponent[];
};

type MdapiComponent = {
  /**
   * Original path to the temporary file
   */
  filePath: string;
  /**
   * Raw file content as string, directly from mdapi retrieve
   */
  fileContent: string;
  /**
   * Unique identifier of the retrieved metadata type
   */
  identifier: string;
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

  public parse(filePath: string): Type[Key] {
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    return this.extract(fileContent);
  }

  public extract(rawFileContent: string): Type[Key] {
    const parsedContent = this.parser.parse(rawFileContent) as Type;
    if (this.opts.parsePostProcessor) {
      return this.opts.parsePostProcessor(parsedContent[this.rootNodeName]);
    }
    return parsedContent[this.rootNodeName];
  }
}

export async function retrieve(compSet: ComponentSet, con: Connection): Promise<ComponentRetrieveResult> {
  const packageName = `metadataPackage_${Date.now()}`;
  fs.mkdirSync(RETRIEVE_CACHE, { recursive: true });
  const retrievePath = path.join(RETRIEVE_CACHE, packageName);
  const retrieveRequest = await compSet.retrieve({
    usernameOrConnection: con,
    format: 'metadata',
    unzip: true,
    singlePackage: true,
    zipFileName: `${packageName}.zip`,
    output: RETRIEVE_CACHE,
  });
  const mdapiRetrieveResult = await retrieveRequest.pollStatus();
  const retrievedComponents = await parseRetrievedComponents(retrievePath);
  cleanRetrieveCache(packageName);
  return {
    mdapiRetrieveResult,
    retrievedComponents,
    packageName,
    retrievePath,
  };
}

export async function parseRetrievedComponents(retrievePath: string): Promise<MdapiComponent[]> {
  const cmpSet = await ComponentSet.fromManifest(path.join(retrievePath, 'package.xml'));
  const parsedComponents: MdapiComponent[] = [];
  for (const mdcmp of cmpSet.toArray()) {
    const filePath = path.join(
      retrievePath,
      mdcmp.type.directoryName,
      mdcmp.type.suffix ? `${mdcmp.fullName}.${mdcmp.type.suffix}` : mdcmp.fullName
    );
    if (fs.existsSync(filePath)) {
      const fileContent = fs.readFileSync(filePath, 'utf-8');
      parsedComponents.push({
        filePath,
        identifier: mdcmp.fullName,
        fileContent,
      });
    }
  }
  return parsedComponents;
}

function cleanRetrieveCache(packageName: string): void {
  fs.rmSync(path.join(RETRIEVE_CACHE, packageName), { recursive: true });
  fs.rmSync(path.join(RETRIEVE_CACHE, `${packageName}.zip`), { force: true });
}
