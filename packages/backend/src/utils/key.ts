type Ctx = {
  request?: {
    getMethod?: () => string | undefined;
    getUrl?: () => string | undefined;
    getPath?: () => string | undefined;
    getQuery?: () => string | undefined;
  };
};

class KeyBuilder {
  private incMethod = false;
  private incHost = false;
  private incPort = false;
  private incPath = false;
  private incQuery = false;
  private incQueryKeys = false;
  private incBasePath = false;
  private paramName: string | null = null;

  withMethod() { this.incMethod = true; return this; }
  withHost()   { this.incHost = true; return this; }
  withPort()   { this.incPort = true; return this; }
  withPath()   { this.incPath = true; return this; }
  withParam(name?: string) { this.paramName = name || null; return this; }

  /** Include the full query string in the key */
  withQuery() { this.incQuery = true; return this; }

  /** Include only the sorted query parameter keys (not values) in the key */
  withQueryKeys() { this.incQueryKeys = true; return this; }

  /** Include only the base path (without trailing filename) in the key. Alias for withPath for directory-like deduplication */
  withBasePath() { this.incBasePath = true; return this; }

  build() {
    return (ctx: Ctx) => {
      const parts: string[] = [];

      const method = ctx?.request?.getMethod ? (ctx.request.getMethod() || "").toLowerCase() : "";
      const urlStr = ctx?.request?.getUrl ? (ctx.request.getUrl() || "") : "";
      const path   = ctx?.request?.getPath ? (ctx.request.getPath() || "") : "";

      let host = "";
      let port = "";
      let pathname = path || "";
      let search = "";

      if (urlStr) {
        try {
          const u = new URL(urlStr);
          host = u.hostname || "";
          pathname = pathname || (u.pathname || "");
          port = u.port || (u.protocol === "https:" ? "443" : (u.protocol === "http:" ? "80" : ""));
          search = u.search || "";
        } catch {
          pathname = pathname || urlStr;
        }
      }

      if (this.incMethod) parts.push(method);
      if (this.incHost) parts.push(host);
      if (this.incPort) parts.push(port);
      if (this.incPath) parts.push(pathname);

      if (this.incBasePath) {
        // Use directory portion of path (strip trailing filename-like segment)
        const basePath = pathname.replace(/\/[^/]*\.[^/]*$/, "/") || pathname;
        parts.push(`base:${basePath}`);
      }

      if (this.incQuery) {
        parts.push(`q:${search}`);
      }

      if (this.incQueryKeys) {
        try {
          const params = new URLSearchParams(search);
          const keys = Array.from(params.keys()).sort();
          parts.push(`qk:${keys.join(",")}`);
        } catch {
          parts.push(`qk:${search}`);
        }
      }

      if (this.paramName) parts.push(`param:${this.paramName}`);

      const key = parts.filter(Boolean).join("|");
      return key || "global";
    };
  }
}

export function keyStrategy() {
  return new KeyBuilder();
}
