import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Config } from "../config/schema.js";
import { createApproveApp, type ApproveAppDeps } from "./approve-app.js";
import { createPublicApp, type PublicAppDeps } from "./public-app.js";

export const LISTEN_HOST = "127.0.0.1";

export interface ListenersConfig {
  listen: Pick<Config["listen"], "public_port" | "approve_port">;
}

export interface StartListenersOptions {
  publicDeps?: PublicAppDeps;
  approveDeps?: ApproveAppDeps;
}

export interface ListenersHandle {
  publicServer: http.Server;
  approveServer: http.Server;
  publicAddress: AddressInfo;
  approveAddress: AddressInfo;
  close: () => Promise<void>;
}

function listenOnLoopback(server: http.Server, port: number, label: string): Promise<AddressInfo> {
  return new Promise<AddressInfo>((resolve, reject) => {
    const onError = (err: NodeJS.ErrnoException): void => {
      server.removeListener("listening", onListening);
      if (err.code === "EADDRINUSE") {
        reject(
          new Error(
            `${label} listener cannot bind ${LISTEN_HOST}:${port}: port ${port} is already in use.`
          )
        );
        return;
      }
      reject(new Error(`${label} listener failed to bind ${LISTEN_HOST}:${port}: ${err.message}`));
    };

    const onListening = (): void => {
      server.removeListener("error", onError);
      const addr = server.address();
      if (addr === null || typeof addr === "string") {
        reject(new Error(`${label} listener did not expose a TCP address.`));
        return;
      }
      resolve(addr);
    };

    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, LISTEN_HOST);
  });
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
    if (typeof server.closeIdleConnections === "function") {
      server.closeIdleConnections();
    }
  });
}

export async function startListeners(
  config: ListenersConfig,
  options?: StartListenersOptions
): Promise<ListenersHandle> {
  const publicApp = createPublicApp(options?.publicDeps);
  const approveApp = createApproveApp(options?.approveDeps);

  const publicServer = http.createServer(publicApp);
  const approveServer = http.createServer(approveApp);

  const publicAddress = await listenOnLoopback(
    publicServer,
    config.listen.public_port,
    "public"
  );

  let approveAddress: AddressInfo;
  try {
    approveAddress = await listenOnLoopback(
      approveServer,
      config.listen.approve_port,
      "approve"
    );
  } catch (err) {
    await closeServer(publicServer).catch(() => undefined);
    throw err;
  }

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) {
      return;
    }
    closed = true;
    await Promise.all([closeServer(publicServer), closeServer(approveServer)]);
  };

  return {
    publicServer,
    approveServer,
    publicAddress,
    approveAddress,
    close
  };
}
