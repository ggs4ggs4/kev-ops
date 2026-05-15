import { createServer } from "node:http";
import { createApp } from "./http/app.js";
import { config } from "./config.js";
import { logger } from "./core/logger.js";

async function main() {
  const { app, shutdown } = await createApp();
  const server = createServer(app);

  server.listen(config.port, config.host, () => {
    logger.info(
      {
        host: config.host,
        port: config.port,
        mcpPath: config.mcpPath,
        publicBaseUrl: config.publicBaseUrl,
      },
      "KEV-OPS MCP server is listening",
    );
  });

  const terminate = async (signal: string) => {
    logger.info({ signal }, "shutting down");
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
    await shutdown();
    process.exit(0);
  };

  process.on("SIGINT", () => {
    void terminate("SIGINT").catch((error) => {
      logger.error({ err: error }, "shutdown failed");
      process.exit(1);
    });
  });
  process.on("SIGTERM", () => {
    void terminate("SIGTERM").catch((error) => {
      logger.error({ err: error }, "shutdown failed");
      process.exit(1);
    });
  });
}

void main().catch((error) => {
  logger.error({ err: error }, "fatal startup error");
  process.exit(1);
});
