export interface VersionCheckResponse {
  offers?: Array<{
    current?: string;
    response?: string;
  }>;
}
