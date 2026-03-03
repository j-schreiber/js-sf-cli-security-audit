import path from 'node:path';

export const MOCK_DATA_BASE_PATH = path.join('test', 'mocks', 'data');

/** this path stores records (-> JSON files with arrays) */
export const QUERY_RESULTS_BASE = path.join(MOCK_DATA_BASE_PATH, 'query-result-records');

/** this path stores full query results (with "done" and "nextRecordsUrl") */
export const FULL_QUERY_RESULTS_BASE = path.join(MOCK_DATA_BASE_PATH, 'query-results');

/** Mocks in source format (new SFDX) */
export const RETRIEVES_BASE = path.join(MOCK_DATA_BASE_PATH, 'retrieves');

/** Mocks in MDAPI retrieve format (legacy) */
export const SRC_MOCKS_BASE_PATH = path.join(MOCK_DATA_BASE_PATH, 'mdapi-retrieve-mocks');
