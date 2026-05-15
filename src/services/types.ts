import type { CacheState } from "../types/domain.js";

export interface ServiceResult<T> {
  data: T;
  cacheState: CacheState;
}
