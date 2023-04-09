export interface VersionCheckResponse {
  offers?: Array<{
    response?: string;
    current?: string;
  }>;
}
