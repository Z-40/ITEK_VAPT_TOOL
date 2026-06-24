export interface ScanResult {
  tool: string;
  target?: string;
  timestamp?: Date;
  data: any;
}

export interface ApiResponse {
  status: string;
  message?: string;
  data?: any;
}