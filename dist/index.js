var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/environment.ts
import { z } from "zod";
var FLOW_MAINNET_PUBLIC_RPC = "https://mainnet.onflow.org";
var flowEnvSchema = z.object({
  FLOW_ADDRESS: z.string().min(1, "Flow native address is required").startsWith("0x", "Flow address must start with 0x"),
  FLOW_PRIVATE_KEY: z.string().min(1, "Flow private key for the address is required").startsWith("0x", "Flow private key must start with 0x"),
  FLOW_NETWORK: z.string().optional().default("mainnet"),
  FLOW_ENDPOINT_URL: z.string().optional().default(FLOW_MAINNET_PUBLIC_RPC)
});
async function validateFlowConfig(runtime) {
  try {
    const config2 = {
      FLOW_ADDRESS: runtime.getSetting("FLOW_ADDRESS") || process.env.FLOW_ADDRESS,
      FLOW_PRIVATE_KEY: runtime.getSetting("FLOW_PRIVATE_KEY") || process.env.FLOW_PRIVATE_KEY,
      FLOW_NETWORK: runtime.getSetting("FLOW_NETWORK") || process.env.FLOW_NETWORK || "mainnet",
      FLOW_ENDPOINT_URL: runtime.getSetting("FLOW_ENDPOINT_URL") || process.env.FLOW_ENDPOINT_URL || FLOW_MAINNET_PUBLIC_RPC
    };
    return flowEnvSchema.parse(config2);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.errors.map((err) => `${err.path.join(".")}: ${err.message}`).join("\n");
      throw new Error(`Flow Blockchain configuration validation failed:
${errorMessages}`);
    }
    throw error;
  }
}
__name(validateFlowConfig, "validateFlowConfig");

// src/helpers/checker.ts
function isUUID(str) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(str);
}
__name(isUUID, "isUUID");
function isFlowAddress(address) {
  const regExp = /^0x[a-fA-F0-9]{16}$/gi;
  return regExp.test(address);
}
__name(isFlowAddress, "isFlowAddress");
function isEVMAddress(address) {
  const regExp = /^0x[a-fA-F0-9]{40}$/gi;
  return regExp.test(address);
}
__name(isEVMAddress, "isEVMAddress");
function isCadenceIdentifier(str) {
  const cadenceIdentifier = /^A\.[0-9a-fA-F]{16}\.[0-9a-zA-Z_]+/;
  return cadenceIdentifier.test(str);
}
__name(isCadenceIdentifier, "isCadenceIdentifier");
function isScriptQueryResponse(res) {
  return res && typeof res === "object" && "ok" in res && typeof res.ok === "boolean";
}
__name(isScriptQueryResponse, "isScriptQueryResponse");

// src/helpers/formater.ts
function formatAgentWalletInfo(character, info) {
  let output = `Here is the Agent<${character.name}>'s Flow wallet information:
`;
  output += formatWalletBalances(info);
  return output;
}
__name(formatAgentWalletInfo, "formatAgentWalletInfo");
function formatWalletInfo(userId, accountName, info = void 0) {
  let output = formatAccountInfoPrefix(userId, accountName);
  if (info === void 0) {
    output += `- No wallet information found, maybe you don't have a wallet yet.`;
  } else {
    output += formatWalletBalances(info);
  }
  return output;
}
__name(formatWalletInfo, "formatWalletInfo");
function formatWalletBalances(info) {
  let output = `- Flow wallet address: ${info.address}
`;
  output += `- FLOW balance: ${info.balance} FLOW
`;
  output += `- Flow wallet's COA(EVM) address: ${info.coaAddress || "unknown"}
`;
  output += `- FLOW balance in COA(EVM) address: ${info.coaBalance ?? 0} FLOW`;
  return output;
}
__name(formatWalletBalances, "formatWalletBalances");
function formatWalletCreated(userId, accountName, newAddress) {
  let output = formatAccountInfoPrefix(userId, accountName);
  output += `- New created address: ${newAddress}`;
  return output;
}
__name(formatWalletCreated, "formatWalletCreated");
function formatAccountInfoPrefix(userId, accountName) {
  let output = "Here is current user's account information:\n";
  output += `- UserId: ${userId}
`;
  output += `- WalletId: ${accountName}
`;
  return output;
}
__name(formatAccountInfoPrefix, "formatAccountInfoPrefix");
function formatTransationSent(txId, network, extra) {
  const baseUrl = network === "testnet" ? "https://testnet.flowscan.io" : "https://flowscan.io";
  const txURL = `${baseUrl}/tx/${txId}/events`;
  return `Transaction Sent: <${txURL}>
${extra ?? ""}`;
}
__name(formatTransationSent, "formatTransationSent");
function formatFlowSpent(fromAddress, spent, agentAddr, gasFee) {
  let output = fromAddress ? `- FLOW spent from ${fromAddress}: ${spent} FLOW
` : "";
  if (gasFee > 0) {
    output += `- GasFee spent from Agent[${agentAddr}]: ${gasFee} FLOW`;
  }
  return output;
}
__name(formatFlowSpent, "formatFlowSpent");

// src/helpers/baseAction.ts
import { inject as inject4, injectable as injectable5, unmanaged } from "inversify";
import { composeContext, elizaLogger as elizaLogger5 } from "@elizaos/core";
import { BaseInjectableAction } from "@elizaos-plugins/plugin-di";

// src/services/wallet.service.ts
import { injectable as injectable4, inject as inject3 } from "inversify";
import { elizaLogger as elizaLogger4, Service } from "@elizaos/core";
import { globalContainer as globalContainer4 } from "@elizaos-plugins/plugin-di";
import * as fcl3 from "@onflow/fcl";

// src/providers/utils/pure.signer.ts
import elliptic from "elliptic";
import { SHA3 } from "sha3";
var PureSigner = class {
  static {
    __name(this, "PureSigner");
  }
  /**
   * Sign a message with a private key
   */
  static signWithKey(privateKeyHex, msg) {
    const ec = new elliptic.ec("p256");
    const key = ec.keyFromPrivate(Buffer.from(privateKeyHex, "hex"));
    const sig = key.sign(this._hashMsg(msg));
    const n = 32;
    const r = sig.r.toArrayLike(Buffer, "be", n);
    const s = sig.s.toArrayLike(Buffer, "be", n);
    return Buffer.concat([
      r.valueOf(),
      s.valueOf()
    ]).toString("hex");
  }
  /**
   * Hash a message
   */
  static _hashMsg(msg) {
    const sha = new SHA3(256);
    sha.update(Buffer.from(msg, "hex"));
    return sha.digest();
  }
};

// src/providers/utils/flow.connector.ts
import * as fcl from "@onflow/fcl";

// src/types/exception.ts
var Exception = class extends Error {
  static {
    __name(this, "Exception");
  }
  code;
  constructor(code, message, options) {
    super(message, options), this.code = code;
  }
};

// src/providers/utils/flow.connector.ts
var isGloballyInited = false;
var globallyPromise = null;
var FlowConnector = class {
  static {
    __name(this, "FlowConnector");
  }
  flowJSON;
  network;
  defaultRpcEndpoint;
  /**
   * Initialize the Flow SDK
   */
  constructor(flowJSON, network = "mainnet", defaultRpcEndpoint = void 0) {
    this.flowJSON = flowJSON;
    this.network = network;
    this.defaultRpcEndpoint = defaultRpcEndpoint;
  }
  /**
   * Get the RPC endpoint
   */
  get rpcEndpoint() {
    switch (this.network) {
      case "mainnet":
        return this.defaultRpcEndpoint ?? "https://mainnet.onflow.org";
      case "testnet":
        return "https://testnet.onflow.org";
      case "emulator":
        return "http://localhost:8888";
      default:
        throw new Exception(5e4, `Network type ${this.network} is not supported`);
    }
  }
  /**
   * Initialize the Flow SDK
   */
  async onModuleInit() {
    if (isGloballyInited) return;
    const cfg = fcl.config();
    await cfg.put("flow.network", this.network);
    await cfg.put("fcl.limit", 9999);
    await cfg.put("accessNode.api", this.rpcEndpoint);
    await cfg.load({
      flowJSON: this.flowJSON
    });
    isGloballyInited = true;
  }
  /**
   * Ensure the Flow SDK is initialized
   */
  async ensureInited() {
    if (isGloballyInited) return;
    if (!globallyPromise) {
      globallyPromise = this.onModuleInit();
    }
    return await globallyPromise;
  }
  /**
   * Get account information
   */
  async getAccount(addr) {
    await this.ensureInited();
    return await fcl.send([
      fcl.getAccount(addr)
    ]).then(fcl.decode);
  }
  /**
   * General method of sending transaction
   */
  async sendTransaction(code, args, mainAuthz, extraAuthz) {
    await this.ensureInited();
    if (typeof mainAuthz !== "undefined") {
      return await fcl.mutate({
        cadence: code,
        args,
        proposer: mainAuthz,
        payer: mainAuthz,
        authorizations: (extraAuthz?.length ?? 0) === 0 ? [
          mainAuthz
        ] : [
          mainAuthz,
          ...extraAuthz
        ]
      });
    }
    return await fcl.mutate({
      cadence: code,
      args
    });
  }
  /**
   * Get transaction status
   */
  async getTransactionStatus(transactionId) {
    await this.ensureInited();
    return await fcl.tx(transactionId).onceExecuted();
  }
  /**
   * Get chain id
   */
  async getChainId() {
    await this.ensureInited();
    return await fcl.getChainId();
  }
  /**
   * Send transaction with single authorization
   */
  async onceTransactionSealed(transactionId) {
    await this.ensureInited();
    return fcl.tx(transactionId).onceSealed();
  }
  /**
   * Get block object
   * @param blockId
   */
  async getBlockHeaderObject(blockId) {
    await this.ensureInited();
    return await fcl.send([
      fcl.getBlockHeader(),
      fcl.atBlockId(blockId)
    ]).then(fcl.decode);
  }
  /**
   * Send script
   */
  async executeScript(code, args, defaultValue) {
    await this.ensureInited();
    try {
      const queryResult = await fcl.query({
        cadence: code,
        args
      });
      return queryResult ?? defaultValue;
    } catch (e) {
      console.error(e);
      return defaultValue;
    }
  }
};
var flow_connector_default = FlowConnector;

// src/providers/utils/flow.wallet.ts
import { elizaLogger } from "@elizaos/core";
import NodeCache from "node-cache";
import * as fcl2 from "@onflow/fcl";
var FlowWallet = class {
  static {
    __name(this, "FlowWallet");
  }
  connector;
  cache;
  runtime;
  privateKeyHex;
  address;
  // Runtime data
  account;
  maxKeyIndex;
  constructor(runtime, connector, cache = new NodeCache({
    stdTTL: 300
  })) {
    this.connector = connector;
    this.cache = cache;
    this.account = null;
    this.maxKeyIndex = 0;
    const signerAddr = runtime.getSetting("FLOW_ADDRESS");
    if (!signerAddr) {
      elizaLogger.error("No signer address");
      throw new Exception(50200, "No signer info");
    }
    this.address = signerAddr;
    this.runtime = runtime;
    const privateKey = runtime.getSetting("FLOW_PRIVATE_KEY");
    if (!privateKey) {
      elizaLogger.warn(`The default Flow wallet ${this.address} has no private key`);
    } else {
      this.privateKeyHex = privateKey.startsWith("0x") ? privateKey.slice(2) : privateKey;
    }
  }
  /**
   * Get the network type
   */
  get network() {
    return this.connector.network;
  }
  /**
   * Send a transaction
   * @param code Cadence code
   * @param args Cadence arguments
   */
  async sendTransaction(code, args, authz) {
    return await this.connector.sendTransaction(code, args, authz ?? this.buildAuthorization());
  }
  /**
   * Execute a script
   * @param code Cadence code
   * @param args Cadence arguments
   */
  async executeScript(code, args, defaultValue) {
    return await this.connector.executeScript(code, args, defaultValue);
  }
  /**
   * Build authorization
   */
  buildAuthorization(accountIndex = 0, privateKey = this.privateKeyHex) {
    if (this.account) {
      if (accountIndex > this.maxKeyIndex) {
        throw new Exception(50200, "Invalid account index");
      }
    }
    const address = this.address;
    if (!privateKey) {
      throw new Exception(50200, "No private key provided");
    }
    return (account) => {
      return {
        ...account,
        addr: fcl2.sansPrefix(address),
        keyId: Number(accountIndex),
        signingFunction: /* @__PURE__ */ __name((signable) => {
          return Promise.resolve({
            f_type: "CompositeSignature",
            f_vsn: "1.0.0",
            addr: fcl2.withPrefix(address),
            keyId: Number(accountIndex),
            signature: this.signMessage(signable.message, privateKey)
          });
        }, "signingFunction")
      };
    };
  }
  /**
   * Sign a message
   * @param message Message to sign
   */
  signMessage(message, privateKey = this.privateKeyHex) {
    return PureSigner.signWithKey(privateKey, message);
  }
  // -----  methods -----
  /**
   * Sync account info
   */
  async syncAccountInfo() {
    this.account = await this.connector.getAccount(this.address);
    this.maxKeyIndex = this.account.keys.length - 1;
    this.cache.set("balance", this.account.balance / 1e8);
    elizaLogger.debug("Flow account info synced", {
      address: this.address,
      balance: this.account.balance,
      maxKeyIndex: this.maxKeyIndex,
      keyAmount: this.account.keys.length
    });
  }
  /**
   * Get the wallet balance
   * @returns Wallet balance
   */
  async getWalletBalance(forceRefresh = false) {
    const cachedBalance = await this.cache.get("balance");
    if (!forceRefresh && cachedBalance) {
      return cachedBalance;
    }
    await this.syncAccountInfo();
    return this.account ? this.account.balance / 1e8 : 0;
  }
};

// src/providers/cache.ts
import path from "node:path";
import { injectable } from "inversify";
import { v4 } from "uuid";
import NodeCache2 from "node-cache";
import { globalContainer } from "@elizaos-plugins/plugin-di";
function _ts_decorate(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate, "_ts_decorate");
function _ts_metadata(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata, "_ts_metadata");
var CacheProvider = class {
  static {
    __name(this, "CacheProvider");
  }
  _nodeCache;
  cacheKey = "eliza-flow/shared-cache";
  CACHE_EXPIRY_SEC = 120;
  providerId;
  _fileCache;
  /**
   * Initialize the Flow connector provider
   * @param flowJSON The Flow JSON object
   */
  constructor() {
    this._nodeCache = new NodeCache2({
      stdTTL: this.CACHE_EXPIRY_SEC
    });
    this.providerId = v4();
  }
  /**
   * Get the cache manager instance
   * @param runtime The runtime object from Eliza framework
   */
  async getInstance(runtime) {
    if (!this._fileCache) {
      this._fileCache = runtime.cacheManager;
    }
    return this._fileCache;
  }
  /**
   * Eliza provider `get` method
   * @returns The message to be injected into the context
   */
  async get(runtime, _message, _state) {
    await this.getInstance(runtime);
    return null;
  }
  /**
   * Get cached data
   */
  async getCachedData(key) {
    const cachedData = this._nodeCache.get(key);
    if (cachedData) {
      return cachedData;
    }
    const fileCachedData = await this._readFromCache(key);
    if (fileCachedData) {
      this._nodeCache.set(key, fileCachedData);
      return fileCachedData;
    }
    return null;
  }
  /**
   * Set cached data in file-based cache
   * @param cacheKey The cache key
   * @param data The data to cache
   * @param ttl The time-to-live in seconds, defaults to 120 seconds, if not provided
   */
  async setCachedData(cacheKey, data, ttl) {
    this._nodeCache.set(cacheKey, data);
    await this._writeToCache(cacheKey, data, ttl);
  }
  // ---- Internal methods ----
  _getFileCacheKey(key) {
    return path.join(this.cacheKey, this.providerId, key);
  }
  async _readFromCache(key) {
    if (!this._fileCache) {
      return null;
    }
    return await this._fileCache.get(this._getFileCacheKey(key));
  }
  async _writeToCache(key, data, ttl) {
    await this._fileCache?.set(this._getFileCacheKey(key), data, {
      expires: Date.now() + (ttl ?? this.CACHE_EXPIRY_SEC) * 1e3
    });
  }
};
CacheProvider = _ts_decorate([
  injectable(),
  _ts_metadata("design:type", Function),
  _ts_metadata("design:paramtypes", [])
], CacheProvider);
globalContainer.bind(CacheProvider).toSelf().inRequestScope();
var cacheProvider = new CacheProvider();

// src/providers/connector.ts
import { injectable as injectable2, inject } from "inversify";
import { elizaLogger as elizaLogger2 } from "@elizaos/core";
import { globalContainer as globalContainer2 } from "@elizaos-plugins/plugin-di";

// src/symbols.ts
var symbols_exports = {};
__export(symbols_exports, {
  CONSTANTS: () => CONSTANTS
});
var CONSTANTS = {
  FlowJSON: Symbol.for("FlowJSON")
};

// flow.json
var flow_default = {
  dependencies: {
    ArrayUtils: {
      source: "mainnet://a340dc0a4ec828ab.ArrayUtils",
      hash: "9e8f2d3e35be82da42b685045af834e16d23bcef1f322603ff91cedd1c9bbad9",
      aliases: {
        mainnet: "a340dc0a4ec828ab",
        testnet: "31ad40c07a2a9788"
      }
    },
    Burner: {
      source: "mainnet://f233dcee88fe0abe.Burner",
      hash: "71af18e227984cd434a3ad00bb2f3618b76482842bae920ee55662c37c8bf331",
      aliases: {
        emulator: "f8d6e0586b0a20c7",
        mainnet: "f233dcee88fe0abe",
        testnet: "9a0766d93b6608b7"
      }
    },
    CapabilityDelegator: {
      source: "mainnet://d8a7e05a7ac670c0.CapabilityDelegator",
      hash: "ad3bf8671a74a836b428da7840540c0ce419349be5f6410b18546e9a9217a9d2",
      aliases: {
        mainnet: "d8a7e05a7ac670c0",
        testnet: "294e44e1ec6993c6"
      }
    },
    CapabilityFactory: {
      source: "mainnet://d8a7e05a7ac670c0.CapabilityFactory",
      hash: "33d6b142c1db548a193cc06ff9828a24ca2ff8726301e292a8b6863dd0e1e73e",
      aliases: {
        mainnet: "d8a7e05a7ac670c0",
        testnet: "294e44e1ec6993c6"
      }
    },
    CapabilityFilter: {
      source: "mainnet://d8a7e05a7ac670c0.CapabilityFilter",
      hash: "77b59eb8245102a84a49d47a67e83eeeaafea920b120cdd6aa175d9ff120c388",
      aliases: {
        mainnet: "d8a7e05a7ac670c0",
        testnet: "294e44e1ec6993c6"
      }
    },
    CrossVMNFT: {
      source: "mainnet://1e4aa0b87d10b141.CrossVMNFT",
      hash: "a9e2ba34ecffda196c58f5c1439bc257d48d0c81457597eb58eb5f879dd95e5a",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    CrossVMToken: {
      source: "mainnet://1e4aa0b87d10b141.CrossVMToken",
      hash: "6d5c16804247ab9f1234b06383fa1bed42845211dba22582748abd434296650c",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    EVM: {
      source: "mainnet://e467b9dd11fa00df.EVM",
      hash: "5c69921fa06088b477e2758e122636b39d3d3eb5316807c206c5680d9ac74c7e",
      aliases: {
        emulator: "f8d6e0586b0a20c7",
        mainnet: "e467b9dd11fa00df",
        testnet: "8c5303eaa26202d6"
      }
    },
    FTViewUtils: {
      source: "mainnet://15a918087ab12d86.FTViewUtils",
      hash: "ef8343697ebcb455a835bc9f87b8060f574c3d968644de47f6613cebf05d7749",
      aliases: {
        mainnet: "15a918087ab12d86",
        testnet: "b86f928a1fa7798e"
      }
    },
    FlowEVMBridge: {
      source: "mainnet://1e4aa0b87d10b141.FlowEVMBridge",
      hash: "83d4d1f7c715cfe7b1a65241e94ae4b8cb40e6ce135ce4c3981e4d39e59ba33e",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    FlowEVMBridgeConfig: {
      source: "mainnet://1e4aa0b87d10b141.FlowEVMBridgeConfig",
      hash: "279513a6c107da2af4c847a42169f862ee67105e5a56512872fb6b9a9be3305d",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    FlowEVMBridgeHandlerInterfaces: {
      source: "mainnet://1e4aa0b87d10b141.FlowEVMBridgeHandlerInterfaces",
      hash: "fcbcd095c8145acf6fd07c336d44502f2946e32f4a1bf7e9bd0772fdd1bea778",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    FlowEVMBridgeNFTEscrow: {
      source: "mainnet://1e4aa0b87d10b141.FlowEVMBridgeNFTEscrow",
      hash: "ea7054bd06f978d09672ab2d6a1e7ad04df4b46410943088d555dd9ca6e64240",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    FlowEVMBridgeTemplates: {
      source: "mainnet://1e4aa0b87d10b141.FlowEVMBridgeTemplates",
      hash: "8f27b22450f57522d93d3045038ac9b1935476f4216f57fe3bb82929c71d7aa6",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    FlowEVMBridgeTokenEscrow: {
      source: "mainnet://1e4aa0b87d10b141.FlowEVMBridgeTokenEscrow",
      hash: "b5ec7c0a16e1c49004b2ed072c5eadc8c382e43351982b4a3050422f116b8f46",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    FlowEVMBridgeUtils: {
      source: "mainnet://1e4aa0b87d10b141.FlowEVMBridgeUtils",
      hash: "cd17ed82ae6d6f708a8d022d4228e0b53d2349f7f330c18e9c45e777553d2173",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    FlowStorageFees: {
      source: "mainnet://e467b9dd11fa00df.FlowStorageFees",
      hash: "e38d8a95f6518b8ff46ce57dfa37b4b850b3638f33d16333096bc625b6d9b51a",
      aliases: {
        emulator: "f8d6e0586b0a20c7",
        mainnet: "e467b9dd11fa00df",
        testnet: "8c5303eaa26202d6"
      }
    },
    FlowToken: {
      source: "mainnet://1654653399040a61.FlowToken",
      hash: "cefb25fd19d9fc80ce02896267eb6157a6b0df7b1935caa8641421fe34c0e67a",
      aliases: {
        emulator: "0ae53cb6e3f42a79",
        mainnet: "1654653399040a61",
        testnet: "7e60df042a9c0868"
      }
    },
    FungibleToken: {
      source: "mainnet://f233dcee88fe0abe.FungibleToken",
      hash: "050328d01c6cde307fbe14960632666848d9b7ea4fef03ca8c0bbfb0f2884068",
      aliases: {
        emulator: "ee82856bf20e2aa6",
        mainnet: "f233dcee88fe0abe",
        testnet: "9a0766d93b6608b7"
      }
    },
    FungibleTokenMetadataViews: {
      source: "mainnet://f233dcee88fe0abe.FungibleTokenMetadataViews",
      hash: "dff704a6e3da83997ed48bcd244aaa3eac0733156759a37c76a58ab08863016a",
      aliases: {
        emulator: "ee82856bf20e2aa6",
        mainnet: "f233dcee88fe0abe",
        testnet: "9a0766d93b6608b7"
      }
    },
    HybridCustody: {
      source: "mainnet://d8a7e05a7ac670c0.HybridCustody",
      hash: "c8a129eec11c57ee25487fcce38efc54c3b12eb539ba61a52f4ee620173bb67b",
      aliases: {
        mainnet: "d8a7e05a7ac670c0",
        testnet: "294e44e1ec6993c6"
      }
    },
    IBridgePermissions: {
      source: "mainnet://1e4aa0b87d10b141.IBridgePermissions",
      hash: "431a51a6cca87773596f79832520b19499fe614297eaef347e49383f2ae809af",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    ICrossVM: {
      source: "mainnet://1e4aa0b87d10b141.ICrossVM",
      hash: "e14dcb25f974e216fd83afdc0d0f576ae7014988755a4777b06562ffb06537bc",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    ICrossVMAsset: {
      source: "mainnet://1e4aa0b87d10b141.ICrossVMAsset",
      hash: "aa1fbd979c9d7806ea8ea66311e2a4257c5a4051eef020524a0bda4d8048ed57",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    IEVMBridgeNFTMinter: {
      source: "mainnet://1e4aa0b87d10b141.IEVMBridgeNFTMinter",
      hash: "65ec734429c12b70cd97ad8ea2c2bc4986fab286744921ed139d9b45da92e77e",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    IEVMBridgeTokenMinter: {
      source: "mainnet://1e4aa0b87d10b141.IEVMBridgeTokenMinter",
      hash: "223adb675415984e9c163d15c5922b5c77dc5036bf6548d0b87afa27f4f0a9d9",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    IFlowEVMNFTBridge: {
      source: "mainnet://1e4aa0b87d10b141.IFlowEVMNFTBridge",
      hash: "3d5bfa663a7059edee8c51d95bc454adf37f17c6d32be18eb42134b550e537b3",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    IFlowEVMTokenBridge: {
      source: "mainnet://1e4aa0b87d10b141.IFlowEVMTokenBridge",
      hash: "573a038b1e9c26504f6aa32a091e88168591b7f93feeff9ac0343285488a8eb3",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    MetadataViews: {
      source: "mainnet://1d7e57aa55817448.MetadataViews",
      hash: "10a239cc26e825077de6c8b424409ae173e78e8391df62750b6ba19ffd048f51",
      aliases: {
        emulator: "f8d6e0586b0a20c7",
        mainnet: "1d7e57aa55817448",
        testnet: "631e88ae7f1d7c20"
      }
    },
    NonFungibleToken: {
      source: "mainnet://1d7e57aa55817448.NonFungibleToken",
      hash: "b63f10e00d1a814492822652dac7c0574428a200e4c26cb3c832c4829e2778f0",
      aliases: {
        emulator: "f8d6e0586b0a20c7",
        mainnet: "1d7e57aa55817448",
        testnet: "631e88ae7f1d7c20"
      }
    },
    OracleConfig: {
      source: "mainnet://cec15c814971c1dc.OracleConfig",
      hash: "48c252a858ce1c1fb44a377f338a4e558a70f1c22cecea9b7bf8cb74e9b16b79",
      aliases: {
        mainnet: "cec15c814971c1dc",
        testnet: "2a9b59c3e2b72ee0"
      }
    },
    OracleInterface: {
      source: "mainnet://cec15c814971c1dc.OracleInterface",
      hash: "1ca66227b60dcf59e9d84404398c8151b1ff6395408094669ef1251c78ca2465",
      aliases: {
        mainnet: "cec15c814971c1dc",
        testnet: "2a9b59c3e2b72ee0"
      }
    },
    PublicPriceOracle: {
      source: "mainnet://ec67451f8a58216a.PublicPriceOracle",
      hash: "3f0b75a98cc8a75835125421bcf602a3f278eaf94001bca7b7a8503b73cbc9a7",
      aliases: {
        mainnet: "ec67451f8a58216a",
        testnet: "8232ce4a3aff4e94"
      }
    },
    ScopedFTProviders: {
      source: "mainnet://a340dc0a4ec828ab.ScopedFTProviders",
      hash: "9a143138f5a5f51a5402715f7d84dbe363b5744be153ee09343aed71cf241c42",
      aliases: {
        mainnet: "a340dc0a4ec828ab",
        testnet: "31ad40c07a2a9788"
      }
    },
    Serialize: {
      source: "mainnet://1e4aa0b87d10b141.Serialize",
      hash: "d12a5957ab5352024bb08b281c4de4f9a88ecde74b159a7da0c69d0c8ca51589",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    SerializeMetadata: {
      source: "mainnet://1e4aa0b87d10b141.SerializeMetadata",
      hash: "eb7ec0ab5abfc66dd636c07a5ed2c7a65723a8d876842035bf9bebd6b0060e3a",
      aliases: {
        mainnet: "1e4aa0b87d10b141",
        testnet: "dfc20aee650fcbdf"
      }
    },
    StableSwapFactory: {
      source: "mainnet://b063c16cac85dbd1.StableSwapFactory",
      hash: "46318aee6fd29616c8048c23210d4c4f5b172eb99a0ca911fbd849c831a52a0b",
      aliases: {
        mainnet: "b063c16cac85dbd1",
        testnet: "cbed4c301441ded2"
      }
    },
    StringUtils: {
      source: "mainnet://a340dc0a4ec828ab.StringUtils",
      hash: "b401c4b0f711344ed9cd02ff77c91e026f5dfbca6045f140b9ca9d4966707e83",
      aliases: {
        mainnet: "a340dc0a4ec828ab",
        testnet: "31ad40c07a2a9788"
      }
    },
    SwapConfig: {
      source: "mainnet://b78ef7afa52ff906.SwapConfig",
      hash: "ccafdb89804887e4e39a9b8fdff5c0ff0d0743505282f2a8ecf86c964e691c82",
      aliases: {
        mainnet: "b78ef7afa52ff906",
        testnet: "ddb929038d45d4b3"
      }
    },
    SwapError: {
      source: "mainnet://b78ef7afa52ff906.SwapError",
      hash: "7d13a652a1308af387513e35c08b4f9a7389a927bddf08431687a846e4c67f21",
      aliases: {
        mainnet: "b78ef7afa52ff906",
        testnet: "ddb929038d45d4b3"
      }
    },
    SwapFactory: {
      source: "mainnet://b063c16cac85dbd1.SwapFactory",
      hash: "6d319e77f5eed0c49c960b1ef887c01dd7c2cce8a0b39f7e31fb2af0113eedc5",
      aliases: {
        mainnet: "b063c16cac85dbd1",
        testnet: "cbed4c301441ded2"
      }
    },
    SwapInterfaces: {
      source: "mainnet://b78ef7afa52ff906.SwapInterfaces",
      hash: "570bb4b9c8da8e0caa8f428494db80779fb906a66cc1904c39a2b9f78b89c6fa",
      aliases: {
        mainnet: "b78ef7afa52ff906",
        testnet: "ddb929038d45d4b3"
      }
    },
    SwapPair: {
      source: "mainnet://ecbda466e7f191c7.SwapPair",
      hash: "69b99c4a8abc123a0a88b1c354f9da414a32e2f73194403e67e89d51713923c0",
      aliases: {
        mainnet: "ecbda466e7f191c7",
        testnet: "c20df20fabe06457"
      }
    },
    TokenList: {
      source: "mainnet://15a918087ab12d86.TokenList",
      hash: "ac9298cfdf02e785e92334858fab0f388e5a72136c3bc4d4ed7f2039ac152bd5",
      aliases: {
        mainnet: "15a918087ab12d86",
        testnet: "b86f928a1fa7798e"
      }
    },
    ViewResolver: {
      source: "mainnet://1d7e57aa55817448.ViewResolver",
      hash: "374a1994046bac9f6228b4843cb32393ef40554df9bd9907a702d098a2987bde",
      aliases: {
        emulator: "f8d6e0586b0a20c7",
        mainnet: "1d7e57aa55817448",
        testnet: "631e88ae7f1d7c20"
      }
    },
    ViewResolvers: {
      source: "mainnet://15a918087ab12d86.ViewResolvers",
      hash: "37ef9b2a71c1b0daa031c261f731466fcbefad998590177c798b56b61a95489a",
      aliases: {
        mainnet: "15a918087ab12d86",
        testnet: "b86f928a1fa7798e"
      }
    },
    stFlowToken: {
      source: "mainnet://d6f80565193ad727.stFlowToken",
      hash: "09b1350a55646fdee652fddf7927fc4b305da5a265cb1bd887e112d84fb5e2be",
      aliases: {
        mainnet: "d6f80565193ad727",
        testnet: "e45c64ecfe31e465"
      }
    }
  },
  networks: {
    emulator: "127.0.0.1:3569",
    mainnet: "access.mainnet.nodes.onflow.org:9000",
    testing: "127.0.0.1:3569",
    testnet: "access.devnet.nodes.onflow.org:9000"
  }
};

// src/providers/connector.ts
function _ts_decorate2(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate2, "_ts_decorate");
function _ts_metadata2(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata2, "_ts_metadata");
function _ts_param(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param, "_ts_param");
async function _createFlowConnector(runtime, flowJSON) {
  const rpcEndpoint = runtime.getSetting("FLOW_ENDPOINT_URL");
  const network = runtime.getSetting("FLOW_NETWORK");
  const instance = new flow_connector_default(flowJSON, network, rpcEndpoint);
  await instance.onModuleInit();
  return instance;
}
__name(_createFlowConnector, "_createFlowConnector");
async function getFlowConnectorInstance(runtime, inputedFlowJSON = void 0) {
  let connector;
  if (inputedFlowJSON && typeof inputedFlowJSON === "object" && typeof inputedFlowJSON?.networks === "object" && typeof inputedFlowJSON?.dependencies === "object") {
    connector = await _createFlowConnector(runtime, inputedFlowJSON);
  } else {
    connector = await _createFlowConnector(runtime, flow_default);
  }
  return connector;
}
__name(getFlowConnectorInstance, "getFlowConnectorInstance");
var ConnectorProvider = class {
  static {
    __name(this, "ConnectorProvider");
  }
  flowJSON;
  _connector;
  /**
   * Initialize the Flow connector provider
   * @param flowJSON The Flow JSON object
   */
  constructor(flowJSON) {
    this.flowJSON = flowJSON;
  }
  /**
   * Get the Flow connector instance
   * @param runtime The runtime object from Eliza framework
   */
  async getInstance(runtime) {
    if (!this._connector) {
      this._connector = await getFlowConnectorInstance(runtime, this.flowJSON);
    }
    return this._connector;
  }
  /**
   * Get the connector status
   * @param runtime The runtime object from Eliza framework
   */
  async getConnectorStatus(runtime) {
    const instance = await this.getInstance(runtime);
    let output = `Now user<${runtime.character.name}> connected to
`;
    output += `Flow network: ${instance.network}
`;
    output += `Flow Endpoint: ${instance.rpcEndpoint}
`;
    return output;
  }
  /**
   * Eliza provider `get` method
   * @returns The message to be injected into the context
   */
  async get(runtime, _message, state) {
    if (state) {
      const CONNECTOR_PROVIDER_SESSION_FLAG = "connector-provider-session";
      if (state[CONNECTOR_PROVIDER_SESSION_FLAG]) {
        return null;
      }
      state[CONNECTOR_PROVIDER_SESSION_FLAG] = true;
    }
    try {
      return await this.getConnectorStatus(runtime);
    } catch (error) {
      elizaLogger2.error("Error in Flow connector provider:", error.message);
      return null;
    }
  }
};
ConnectorProvider = _ts_decorate2([
  injectable2(),
  _ts_param(0, inject(CONSTANTS.FlowJSON)),
  _ts_metadata2("design:type", Function),
  _ts_metadata2("design:paramtypes", [
    typeof Record === "undefined" ? Object : Record
  ])
], ConnectorProvider);
globalContainer2.bind(ConnectorProvider).toSelf().inSingletonScope();
var flowConnectorProvider = new ConnectorProvider(flow_default);

// src/providers/wallet.ts
import { injectable as injectable3, inject as inject2 } from "inversify";
import { elizaLogger as elizaLogger3 } from "@elizaos/core";
import { globalContainer as globalContainer3 } from "@elizaos-plugins/plugin-di";

// src/queries.ts
var queries_exports = {};
__export(queries_exports, {
  queryAccountBalanceInfo: () => queryAccountBalanceInfo,
  queryEvmERC20BalanceOf: () => queryEvmERC20BalanceOf,
  queryEvmERC20Decimals: () => queryEvmERC20Decimals,
  queryEvmERC20TotalSupply: () => queryEvmERC20TotalSupply
});

// src/assets/cadence/scripts/evm/call.cdc
var call_default = 'import "EVM"\n\naccess(all) fun getTypeArray(_ identifiers: [String]): [Type] {\n    var types: [Type] = []\n    for identifier in identifiers {\n        let type = CompositeType(identifier)\n            ?? panic("Invalid identifier: ".concat(identifier))\n        types.append(type)\n    }\n    return types\n}\n\n/// Supports generic calls to EVM contracts that might have return values\n///\naccess(all) fun main(\n    gatewayAddress: Address,\n    evmContractAddressHex: String,\n    calldata: String,\n    gasLimit: UInt64,\n    typeIdentifiers: [String]\n): [AnyStruct] {\n\n    let evmAddress = EVM.addressFromString(evmContractAddressHex)\n\n    let data = calldata.decodeHex()\n\n    let gatewayCOA = getAuthAccount<auth(BorrowValue) &Account>(gatewayAddress)\n        .storage.borrow<auth(EVM.Call) &EVM.CadenceOwnedAccount>(\n            from: /storage/evm\n        ) ?? panic("Could not borrow COA from provided gateway address")\n\n    let evmResult = gatewayCOA.call(\n        to: evmAddress,\n        data: data,\n        gasLimit: gasLimit,\n        value: EVM.Balance(attoflow: 0)\n    )\n\n    return EVM.decodeABI(types: getTypeArray(typeIdentifiers), data: evmResult.data)\n}\n';

// src/assets/cadence/scripts/evm/erc20/balance_of.cdc
var balance_of_default = 'import "EVM"\n\nimport "FlowEVMBridgeUtils"\n\n/// Returns the balance of the owner (hex-encoded EVM address) of a given ERC20 fungible token defined\n/// at the hex-encoded EVM contract address\n///\n/// @param owner: The hex-encoded EVM address of the owner\n/// @param evmContractAddress: The hex-encoded EVM contract address of the ERC20 contract\n///\n/// @return The balance of the address, reverting if the given contract address does not implement the ERC20 method\n///     "balanceOf(address)(uint256)"\n///\naccess(all) fun main(owner: String, evmContractAddress: String): UInt256 {\n    return FlowEVMBridgeUtils.balanceOf(\n        owner: EVM.addressFromString(owner),\n        evmContractAddress: EVM.addressFromString(evmContractAddress)\n    )\n}\n';

// src/assets/cadence/scripts/evm/erc20/get_decimals.cdc
var get_decimals_default = 'import "EVM"\n\nimport "FlowEVMBridgeUtils"\n\naccess(all)\nfun main(erc20ContractAddressHex: String): UInt8 {\n    return FlowEVMBridgeUtils.getTokenDecimals(\n        evmContractAddress: EVM.addressFromString(erc20ContractAddressHex)\n    )\n}\n';

// src/assets/cadence/scripts/evm/erc20/total_supply.cdc
var total_supply_default = 'import "EVM"\n\nimport "FlowEVMBridgeUtils"\n\n/// Retrieves the total supply of the ERC20 contract at the given EVM contract address. Reverts on EVM call failure.\n///\n/// @param evmContractAddress: The EVM contract address to retrieve the total supply from\n///\n/// @return the total supply of the ERC20\n///\naccess(all) fun main(evmContractAddressHex: String): UInt256 {\n    return FlowEVMBridgeUtils.totalSupply(\n        evmContractAddress: EVM.addressFromString(evmContractAddressHex)\n    )\n}\n';

// src/assets/cadence/scripts/main-account/get_acct_info.cdc
var get_acct_info_default = 'import "FungibleToken"\nimport "EVM"\n\n/// Returns the hex encoded address of the COA in the given Flow address\n///\naccess(all) fun main(flowAddress: Address): AccountInfo {\n    var flowBalance: UFix64 = 0.0\n    if let flowVaultRef = getAccount(flowAddress)\n        .capabilities.get<&{FungibleToken.Balance}>(/public/flowTokenBalance)\n        .borrow() {\n        flowBalance = flowVaultRef.balance\n    }\n\n    var coaAddress: String? = nil\n    var coaBalance: UFix64? = nil\n\n    if let address: EVM.EVMAddress = getAuthAccount<auth(BorrowValue) &Account>(flowAddress)\n        .storage.borrow<&EVM.CadenceOwnedAccount>(from: /storage/evm)?.address() {\n        let bytes: [UInt8] = []\n        for byte in address.bytes {\n            bytes.append(byte)\n        }\n        coaAddress = String.encodeHex(bytes)\n        coaBalance = address.balance().inFLOW()\n    }\n    return AccountInfo(\n        flowAddress,\n        flowBalance,\n        coaAddress,\n        coaBalance\n    )\n}\n\naccess(all) struct AccountInfo {\n    access(all) let address: Address\n    access(all) let balance: UFix64\n    access(all) let coaAddress: String?\n    access(all) let coaBalance: UFix64?\n\n    init(\n        _ address: Address,\n        _ balance: UFix64,\n        _ coaAddress: String?,\n        _ coaBalance: UFix64?\n    ) {\n        self.address = address\n        self.balance = balance\n        self.coaAddress = coaAddress\n        self.coaBalance = coaBalance\n    }\n}\n';

// src/assets/script.defs.ts
var scripts = {
  evmCall: call_default,
  evmERC20BalanceOf: balance_of_default,
  evmERC20GetDecimals: get_decimals_default,
  evmERC20GetTotalSupply: total_supply_default,
  mainGetAccountInfo: get_acct_info_default
};

// src/queries.ts
async function queryEvmERC20BalanceOf(executor, owner, evmContractAddress) {
  const ret = await executor.executeScript(scripts.evmERC20BalanceOf, (arg, t) => [
    arg(owner, t.String),
    arg(evmContractAddress, t.String)
  ], BigInt(0));
  return BigInt(ret);
}
__name(queryEvmERC20BalanceOf, "queryEvmERC20BalanceOf");
async function queryEvmERC20Decimals(executor, evmContractAddress) {
  const ret = await executor.executeScript(scripts.evmERC20GetDecimals, (arg, t) => [
    arg(evmContractAddress, t.String)
  ], "0");
  return Number.parseInt(ret);
}
__name(queryEvmERC20Decimals, "queryEvmERC20Decimals");
async function queryEvmERC20TotalSupply(executor, evmContractAddress) {
  const ret = await executor.executeScript(scripts.evmERC20GetTotalSupply, (arg, t) => [
    arg(evmContractAddress, t.String)
  ], BigInt(0));
  return BigInt(ret);
}
__name(queryEvmERC20TotalSupply, "queryEvmERC20TotalSupply");
async function queryAccountBalanceInfo(executor, address) {
  const ret = await executor.executeScript(scripts.mainGetAccountInfo, (arg, t) => [
    arg(address, t.Address)
  ], void 0);
  if (!ret) {
    return void 0;
  }
  return {
    address: ret.address,
    balance: Number.parseFloat(ret.balance),
    coaAddress: ret.coaAddress,
    coaBalance: ret.coaBalance ? Number.parseFloat(ret.coaBalance) : void 0
  };
}
__name(queryAccountBalanceInfo, "queryAccountBalanceInfo");

// src/providers/wallet.ts
function _ts_decorate3(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate3, "_ts_decorate");
function _ts_metadata3(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata3, "_ts_metadata");
function _ts_param2(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param2, "_ts_param");
var WalletProvider = class {
  static {
    __name(this, "WalletProvider");
  }
  connector;
  _wallet;
  constructor(connector) {
    this.connector = connector;
  }
  /**
   * Get the Flow wallet instance
   * @param runtime The runtime object from Eliza framework
   */
  async getInstance(runtime) {
    if (!this._wallet) {
      const connectorIns = await this.connector.getInstance(runtime);
      this._wallet = new FlowWallet(runtime, connectorIns);
    }
    return this._wallet;
  }
  /**
   * Eliza provider `get` method
   * @returns The message to be injected into the context
   */
  async get(runtime, _message, state) {
    if (state) {
      const WALLET_PROVIDER_SESSION_FLAG = "wallet-provider-session";
      if (state[WALLET_PROVIDER_SESSION_FLAG]) {
        return null;
      }
      state[WALLET_PROVIDER_SESSION_FLAG] = true;
    }
    if (!runtime.getSetting("FLOW_ADDRESS") || !runtime.getSetting("FLOW_PRIVATE_KEY")) {
      elizaLogger3.error("FLOW_ADDRESS or FLOW_PRIVATE_KEY not configured, skipping wallet injection");
      return null;
    }
    try {
      const walletProvider = await this.getInstance(runtime);
      const info = await queryAccountBalanceInfo(walletProvider, walletProvider.address);
      if (!info || info?.address !== walletProvider.address) {
        elizaLogger3.error("Invalid account info");
        return null;
      }
      let output = `Here is user<${runtime.character.name}>'s wallet status:
`;
      output += formatWalletBalances(info);
      return output;
    } catch (error) {
      elizaLogger3.error("Error in Flow wallet provider:", error.message);
      return null;
    }
  }
};
WalletProvider = _ts_decorate3([
  injectable3(),
  _ts_param2(0, inject2(ConnectorProvider)),
  _ts_metadata3("design:type", Function),
  _ts_metadata3("design:paramtypes", [
    typeof ConnectorProvider === "undefined" ? Object : ConnectorProvider
  ])
], WalletProvider);
globalContainer3.bind(WalletProvider).toSelf().inRequestScope();
var flowWalletProvider = new WalletProvider(flowConnectorProvider);

// src/services/wallet.service.ts
function _ts_decorate4(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate4, "_ts_decorate");
function _ts_metadata4(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata4, "_ts_metadata");
function _ts_param3(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param3, "_ts_param");
var FlowWalletService = class _FlowWalletService extends Service {
  static {
    __name(this, "FlowWalletService");
  }
  connectorProvider;
  walletProvider;
  static isInitialized = false;
  _runtime;
  _connector;
  _wallet;
  _maxKeyIndex;
  keysInUse;
  keysTrackingPayloads;
  constructor(connectorProvider, walletProvider) {
    super(), this.connectorProvider = connectorProvider, this.walletProvider = walletProvider, this._runtime = null, this.keysInUse = /* @__PURE__ */ new Set(), this.keysTrackingPayloads = /* @__PURE__ */ new Map();
  }
  static get serviceType() {
    return "flow-wallet";
  }
  async initialize(runtime) {
    if (_FlowWalletService.isInitialized) {
      return;
    }
    this._runtime = runtime;
    this._wallet = await this.walletProvider.getInstance(runtime);
    this._connector = await this.connectorProvider.getInstance(runtime);
    const acctInfo = await this._connector.getAccount(this._wallet.address);
    this._maxKeyIndex = acctInfo.keys.length;
    _FlowWalletService.isInitialized = true;
  }
  /**
   * Whether the service is initialized or not.
   */
  get isInitialized() {
    return _FlowWalletService.isInitialized;
  }
  /**
   * Get the Flow connector
   */
  get connector() {
    return this._connector;
  }
  /**
   * Get the wallet provider
   */
  get wallet() {
    return this._wallet;
  }
  /**
   * Get the wallet address
   */
  get address() {
    return this._wallet.address;
  }
  /**
   * Get maximum key index of the wallet
   */
  get maxKeyIndex() {
    return this._maxKeyIndex;
  }
  /// ----- User methods -----
  /**
   * Execute a script with available account key index of the wallet
   * @param code
   * @param argsFunc
   * @param defaultValue
   * @returns
   */
  async executeScript(code, argsFunc, defaultValue) {
    return await this._wallet.executeScript(code, argsFunc, defaultValue);
  }
  /**
   * Send transction with available account key index of the wallet
   * @param code
   * @param argsFunc
   * @returns
   */
  async sendTransaction(code, argsFunc, callbacks) {
    const index = await this.acquireAndLockIndex();
    if (index < 0) {
      throw new Error("No available account key index to send transaction");
    }
    try {
      const txId = await this._wallet.sendTransaction(code, argsFunc, this._wallet.buildAuthorization(index));
      if (txId) {
        await this.startTransactionTrackingSubstribe(index, txId, callbacks);
      }
      return {
        txId,
        index
      };
    } catch (error) {
      await this.ackAndUnlockIndex(index);
      throw error;
    }
  }
  /// ----- Methods for convenience -----
  /**
   * Get the wallet account info
   */
  async getWalletAccountInfo() {
    return queryAccountBalanceInfo(this.wallet, this.address);
  }
  /// ----- Internal methods -----
  /**
   * Start the service
   */
  async startTransactionTrackingSubstribe(index, txid, callbacks) {
    if (this.keysTrackingPayloads.has(index)) {
      const payload = this.keysTrackingPayloads.get(index);
      payload.unsubscribe();
      this.keysTrackingPayloads.delete(index);
      await this.ackAndUnlockIndex(index);
    }
    elizaLogger4.info(`FlowWalletService: Starting transaction tracking task for txid: ${txid}`);
    let isFinalizedSent = false;
    const unsub = fcl3.tx(txid).subscribe((res) => {
      callbacks?.onStatusUpdated?.(txid, res);
      if (res.status >= 3) {
        if (!isFinalizedSent) {
          callbacks?.onFinalized?.(txid, res, res.errorMessage);
          isFinalizedSent = true;
          this.ackAndUnlockIndex(index);
        }
        if (res.status >= 4) {
          callbacks?.onSealed?.(txid, res, res.errorMessage);
          unsub();
        }
      }
    });
    this.keysTrackingPayloads.set(index, {
      txId: txid,
      unsubscribe: unsub
    });
  }
  /**
   * Acquire and lock an available account key index
   * @returns
   */
  async acquireAndLockIndex() {
    for (let i = 0; i < this._maxKeyIndex; i++) {
      if (!this.keysInUse.has(i)) {
        this.keysInUse.add(i);
        return i;
      }
    }
    return -1;
  }
  /**
   * Acknowledge and unlock an account key index
   * @param index
   */
  async ackAndUnlockIndex(index) {
    if (index >= 0 && index < this._maxKeyIndex && this.keysInUse.has(index)) {
      this.keysInUse.delete(index);
    }
  }
};
FlowWalletService = _ts_decorate4([
  injectable4(),
  _ts_param3(0, inject3(ConnectorProvider)),
  _ts_param3(1, inject3(WalletProvider)),
  _ts_metadata4("design:type", Function),
  _ts_metadata4("design:paramtypes", [
    typeof ConnectorProvider === "undefined" ? Object : ConnectorProvider,
    typeof WalletProvider === "undefined" ? Object : WalletProvider
  ])
], FlowWalletService);
globalContainer4.bind(FlowWalletService).toSelf().inSingletonScope();

// src/helpers/baseAction.ts
function _ts_decorate5(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate5, "_ts_decorate");
function _ts_metadata5(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata5, "_ts_metadata");
function _ts_param4(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param4, "_ts_param");
var BaseFlowInjectableAction = class extends BaseInjectableAction {
  static {
    __name(this, "BaseFlowInjectableAction");
  }
  // -------- Injects --------
  // Inject the Flow Eliza Provider
  walletElizaProvider;
  // Inject the Flow wallet serivce
  walletSerivce;
  /**
   * Constructor for the base injectable action
   */
  constructor(opts) {
    super(opts);
  }
  // -------- Implemented methods for Eliza runtime --------
  /**
   * Default implementation of the validate method
   * You can override this method to add custom validation logic
   *
   * @param runtime The runtime object from Eliza framework
   * @param message The message object from Eliza framework
   * @param state The state object from Eliza framework
   * @returns The validation result
   */
  async validate(runtime, _message, _state) {
    await validateFlowConfig(runtime);
    try {
      await this.walletSerivce.wallet.getWalletBalance();
    } catch {
      elizaLogger5.error("Failed to sync account info");
      return false;
    }
    return true;
  }
  /**
   * Default implementation of the preparation of action context
   * You can override this method to add custom logic
   */
  async prepareActionContext(runtime, message, state) {
    let currentState;
    if (!state) {
      currentState = await runtime.composeState(message);
    } else {
      currentState = await runtime.updateRecentMessageState(state);
    }
    const walletInfo = await this.walletElizaProvider.get(runtime, message);
    state.walletInfo = walletInfo;
    return composeContext({
      state: currentState,
      template: this.template
    });
  }
  /**
   * Default Handler function type for processing messages
   * You can override this method to add custom logic
   *
   * @param runtime The runtime object from Eliza framework
   * @param message The message object from Eliza framework
   * @param state The state object from Eliza framework
   * @param options The options object from Eliza framework
   * @param callback The callback function to pass the result to Eliza runtime
   */
  async handler(runtime, message, state, options, callback) {
    const res = await super.handler(runtime, message, state, options, callback);
    if (res) {
      if (isScriptQueryResponse(res)) {
        if (res.ok) {
          elizaLogger5.log("Action executed with script query successfully with data: ", JSON.stringify(res.data));
        } else {
          elizaLogger5.error("Action executed with script query failed: ", res.errorMessage ?? res.error ?? "Unknown error");
        }
      } else {
        const { signer, txid } = res;
        elizaLogger5.log(`Action executed with transaction: ${signer.address}[${signer.keyIndex}] - ${txid}`);
      }
    }
  }
};
_ts_decorate5([
  inject4(WalletProvider),
  _ts_metadata5("design:type", typeof WalletProvider === "undefined" ? Object : WalletProvider)
], BaseFlowInjectableAction.prototype, "walletElizaProvider", void 0);
_ts_decorate5([
  inject4(FlowWalletService),
  _ts_metadata5("design:type", typeof FlowWalletService === "undefined" ? Object : FlowWalletService)
], BaseFlowInjectableAction.prototype, "walletSerivce", void 0);
BaseFlowInjectableAction = _ts_decorate5([
  injectable5(),
  _ts_param4(0, unmanaged()),
  _ts_metadata5("design:type", Function),
  _ts_metadata5("design:paramtypes", [
    typeof ActionOptions === "undefined" ? Object : ActionOptions
  ])
], BaseFlowInjectableAction);

// src/di.ts
import fs from "node:fs";
import path2 from "node:path";
import { elizaLogger as elizaLogger6 } from "@elizaos/core";
import { globalContainer as globalContainer5 } from "@elizaos-plugins/plugin-di";
globalContainer5.bind(CONSTANTS.FlowJSON).toDynamicValue(async () => {
  const cwd = process.cwd();
  const pathsToTry = [
    path2.resolve(cwd, "flow.json"),
    path2.resolve(cwd, "agent", "flow.json"),
    path2.resolve(cwd, "../flow.json"),
    path2.resolve(cwd, "../../flow.json"),
    path2.resolve(cwd, "../../../flow.json")
  ];
  elizaLogger6.info("Trying loading 'flow.json' paths:", pathsToTry.map((p) => ({
    path: p,
    exists: fs.existsSync(p)
  })));
  let jsonObjcet = null;
  for (const tryPath of pathsToTry) {
    try {
      jsonObjcet = (await import(tryPath, {
        with: {
          type: "json"
        }
      })).default;
      if (jsonObjcet) {
        elizaLogger6.info(`Successfully loaded 'flow.json' from: ${tryPath}`);
        break;
      }
    } catch {
    }
  }
  if (!jsonObjcet) {
    elizaLogger6.error("Cannot find 'flow.json' file");
    throw new Error("Cannot find 'flow.json' file");
  }
  return jsonObjcet;
});

// src/assets/cadence/transactions/evm/call.cdc
var call_default2 = `import "EVM"

/// Executes the calldata from the signer's COA
///
transaction(evmContractAddressHex: String, calldata: String, gasLimit: UInt64, value: UFix64) {

    let evmAddress: EVM.EVMAddress
    let coa: auth(EVM.Call) &EVM.CadenceOwnedAccount

    prepare(signer: auth(BorrowValue) &Account) {
        self.evmAddress = EVM.addressFromString(evmContractAddressHex)

        let storagePath = StoragePath(identifier: "evm")!
        let publicPath = PublicPath(identifier: "evm")!

        // Reference signer's COA if one exists
        let coa = signer.storage.borrow<auth(EVM.Withdraw) &EVM.CadenceOwnedAccount>(from: storagePath)
        if coa == nil {
            let coa <- EVM.createCadenceOwnedAccount()
            signer.storage.save<@EVM.CadenceOwnedAccount>(<-coa, to: storagePath)
            let addressableCap = signer.capabilities.storage.issue<&EVM.CadenceOwnedAccount>(storagePath)
            signer.capabilities.unpublish(publicPath)
            signer.capabilities.publish(addressableCap, at: publicPath)
        }

        self.coa = signer.storage.borrow<auth(EVM.Call) &EVM.CadenceOwnedAccount>(from: storagePath)
            ?? panic("Could not borrow COA from provided gateway address")
    }

    execute {
        let valueBalance = EVM.Balance(attoflow: 0)
        valueBalance.setFLOW(flow: value)
        let callResult = self.coa.call(
            to: self.evmAddress,
            data: calldata.decodeHex(),
            gasLimit: gasLimit,
            value: valueBalance
        )
        assert(callResult.status == EVM.Status.successful, message: "Call failed")
    }
}
`;

// src/assets/cadence/transactions/main-account/account/create_new_account_with_coa.cdc
var create_new_account_with_coa_default = `import Crypto

import "EVM"

/// Creates a new Flow Address with a single full-weight key and its EVM account, which is
/// a Cadence Owned Account (COA) stored in the account's storage.
///
transaction(
    key: String,  // key to be used for the account
    signatureAlgorithm: UInt8, // signature algorithm to be used for the account
    hashAlgorithm: UInt8, // hash algorithm to be used for the account
) {
    let auth: auth(BorrowValue) &Account

    prepare(signer: auth(BorrowValue) &Account) {
        pre {
            signatureAlgorithm == 1 || signatureAlgorithm == 2:
                "Cannot add Key: Must provide a signature algorithm raw value that corresponds to "
                .concat("one of the available signature algorithms for Flow keys.")
                .concat("You provided ").concat(signatureAlgorithm.toString())
                .concat(" but the options are either 1 (ECDSA_P256), 2 (ECDSA_secp256k1).")
            hashAlgorithm == 1 || hashAlgorithm == 3:
                "Cannot add Key: Must provide a hash algorithm raw value that corresponds to "
                .concat("one of of the available hash algorithms for Flow keys.")
                .concat("You provided ").concat(hashAlgorithm.toString())
                .concat(" but the options are 1 (SHA2_256), 3 (SHA3_256).")
        }

        self.auth = signer
    }

    execute {
        // Create a new public key
        let publicKey = PublicKey(
            publicKey: key.decodeHex(),
            signatureAlgorithm: SignatureAlgorithm(rawValue: signatureAlgorithm)!
        )

        // Create a new account
        let account = Account(payer: self.auth)

        // Add the public key to the account
        account.keys.add(
            publicKey: publicKey,
            hashAlgorithm: HashAlgorithm(rawValue: hashAlgorithm)!,
            weight: 1000.0
        )

        // Create a new COA
        let coa <- EVM.createCadenceOwnedAccount()

        // Save the COA to the new account
        let storagePath = StoragePath(identifier: "evm")!
        let publicPath = PublicPath(identifier: "evm")!
        account.storage.save<@EVM.CadenceOwnedAccount>(<-coa, to: storagePath)
        let addressableCap = account.capabilities.storage.issue<&EVM.CadenceOwnedAccount>(storagePath)
        account.capabilities.unpublish(publicPath)
        account.capabilities.publish(addressableCap, at: publicPath)
    }
}
`;

// src/assets/cadence/transactions/main-account/account/setup_coa.cdc
var setup_coa_default = `import "EVM"
import "FungibleToken"
import "FlowToken"

/// Creates a COA and saves it in the signer's Flow account & passing the given value of Flow into FlowEVM
///
transaction() {

    prepare(signer: auth(BorrowValue, IssueStorageCapabilityController, PublishCapability, SaveValue, UnpublishCapability) &Account) {
        let storagePath = StoragePath(identifier: "evm")!
        let publicPath = PublicPath(identifier: "evm")!

        // Reference signer's COA if one exists
        let coa = signer.storage.borrow<auth(EVM.Withdraw) &EVM.CadenceOwnedAccount>(from: storagePath)
        if coa == nil {
            let coa <- EVM.createCadenceOwnedAccount()
            signer.storage.save<@EVM.CadenceOwnedAccount>(<-coa, to: storagePath)
            let addressableCap = signer.capabilities.storage.issue<&EVM.CadenceOwnedAccount>(storagePath)
            signer.capabilities.unpublish(publicPath)
            signer.capabilities.publish(addressableCap, at: publicPath)
        }
    }
}
`;

// src/assets/cadence/transactions/main-account/evm/transfer_erc20.cdc
var transfer_erc20_default = 'import "EVM"\n\nimport "FlowEVMBridgeUtils"\n\n/// Executes a token transfer to the defined recipient address against the specified ERC20 contract.\n///\ntransaction(evmContractAddressHex: String, recipientAddressHex: String, amount: UInt256) {\n\n    let evmContractAddress: EVM.EVMAddress\n    let recipientAddress: EVM.EVMAddress\n    let coa: auth(EVM.Call) &EVM.CadenceOwnedAccount\n    let preBalance: UInt256\n    var postBalance: UInt256\n\n    prepare(signer: auth(BorrowValue) &Account) {\n        self.evmContractAddress = EVM.addressFromString(evmContractAddressHex)\n        self.recipientAddress = EVM.addressFromString(recipientAddressHex)\n\n        self.coa = signer.storage.borrow<auth(EVM.Call) &EVM.CadenceOwnedAccount>(from: /storage/evm)\n            ?? panic("Could not borrow CadenceOwnedAccount reference")\n\n        self.preBalance = FlowEVMBridgeUtils.balanceOf(owner: self.coa.address(), evmContractAddress: self.evmContractAddress)\n        self.postBalance = 0\n    }\n\n    execute {\n        let calldata = EVM.encodeABIWithSignature("transfer(address,uint256)", [self.recipientAddress, amount])\n        let callResult = self.coa.call(\n            to: self.evmContractAddress,\n            data: calldata,\n            gasLimit: 15_000_000,\n            value: EVM.Balance(attoflow: 0)\n        )\n        assert(callResult.status == EVM.Status.successful, message: "Call to ERC20 contract failed")\n        self.postBalance = FlowEVMBridgeUtils.balanceOf(owner: self.coa.address(), evmContractAddress: self.evmContractAddress)\n    }\n\n    post {\n        self.postBalance == self.preBalance - amount: "Transfer failed"\n    }\n}\n';

// src/assets/cadence/transactions/main-account/flow-token/dynamic_vm_transfer.cdc
var dynamic_vm_transfer_default = `import "FungibleToken"
import "FlowToken"

import "EVM"

// Transfers $FLOW from the signer's account to the recipient's address, determining the target VM based on the format
// of the recipient's hex address. Note that the sender's funds are sourced by default from the target VM, pulling any
// difference from the alternate VM if available. e.g. Transfers to Flow addresses will first attempt to withdraw from
// the signer's Flow vault, pulling any remaining funds from the signer's EVM account if available. Transfers to EVM
// addresses will first attempt to withdraw from the signer's EVM account, pulling any remaining funds from the signer's
// Flow vault if available. If the signer's balance across both VMs is insufficient, the transaction will revert.
///
/// @param addressString: The recipient's address in hex format - this should be either an EVM address or a Flow address
/// @param amount: The amount of $FLOW to transfer as a UFix64 value
///
transaction(addressString: String, amount: UFix64) {

    let sentVault: @FlowToken.Vault
    let evmRecipient: EVM.EVMAddress?
    var receiver: &{FungibleToken.Receiver}?

    prepare(signer: auth(BorrowValue, SaveValue) &Account) {
        // Reference signer's COA if one exists
        let coa = signer.storage.borrow<auth(EVM.Withdraw) &EVM.CadenceOwnedAccount>(from: /storage/evm)

        // Reference signer's FlowToken Vault
        let sourceVault = signer.storage.borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)
            ?? panic("Could not borrow signer's FlowToken.Vault")
        let cadenceBalance = sourceVault.balance

        // Define optional recipients for both VMs
        self.receiver = nil
        let cadenceRecipient = Address.fromString(addressString)
        self.evmRecipient = cadenceRecipient == nil ? EVM.addressFromString(addressString) : nil
        // Validate exactly one target address is assigned
        if cadenceRecipient != nil && self.evmRecipient != nil {
            panic("Malformed recipient address - assignable as both Cadence and EVM addresses")
        } else if cadenceRecipient == nil && self.evmRecipient == nil {
            panic("Malformed recipient address - not assignable as either Cadence or EVM address")
        }

        // Create empty FLOW vault to capture funds
        self.sentVault <- FlowToken.createEmptyVault(vaultType: Type<@FlowToken.Vault>())
        /// If the target VM is Flow, does the Vault have sufficient balance to cover?
        if cadenceRecipient != nil {
            // Assign the Receiver of the $FLOW transfer
            self.receiver = getAccount(cadenceRecipient!).capabilities.borrow<&{FungibleToken.Receiver}>(
                    /public/flowTokenReceiver
                ) ?? panic("Could not borrow reference to recipient's FungibleToken.Receiver")

            // Withdraw from the signer's Cadence Vault and deposit to sentVault
            var withdrawAmount = amount < cadenceBalance ? amount : cadenceBalance
            self.sentVault.deposit(from: <-sourceVault.withdraw(amount: withdrawAmount))

            // If the cadence balance didn't cover the amount, check the signer's EVM balance
            if amount > self.sentVault.balance {
                let difference = amount - cadenceBalance
                // Revert if the signer doesn't have an EVM account or EVM balance is insufficient
                if coa == nil || difference < coa!.balance().inFLOW() {
                    panic("Insufficient balance across Flow and EVM accounts")
                }

                // Withdraw from the signer's EVM account and deposit to sentVault
                let withdrawFromEVM = EVM.Balance(attoflow: 0)
                withdrawFromEVM.setFLOW(flow: difference)
                self.sentVault.deposit(from: <-coa!.withdraw(balance: withdrawFromEVM))
            }
        } else if self.evmRecipient != nil {
            // Check signer's balance can cover the amount
            if coa != nil {
                // Determine the amount to withdraw from the signer's EVM account
                let balance = coa!.balance()
                let withdrawAmount = amount < balance.inFLOW() ? amount : balance.inFLOW()
                balance.setFLOW(flow: withdrawAmount)

                // Withdraw funds from EVM to the sentVault
                self.sentVault.deposit(from: <-coa!.withdraw(balance: balance))
            }
            if amount > self.sentVault.balance {
                // Insufficient amount withdrawn from EVM, check signer's Flow balance
                let difference = amount - self.sentVault.balance
                if difference > cadenceBalance {
                    panic("Insufficient balance across Flow and EVM accounts")
                }
                // Withdraw from the signer's Cadence Vault and deposit to sentVault
                self.sentVault.deposit(from: <-sourceVault.withdraw(amount: difference))
            }
        }
    }

    pre {
        self.sentVault.balance == amount: "Attempting to send an incorrect amount of $FLOW"
    }

    execute {
        // Complete Cadence transfer if the FungibleToken Receiver is assigned
        if self.receiver != nil {
            self.receiver!.deposit(from: <-self.sentVault)
        } else {
            // Otherwise, complete EVM transfer
            self.evmRecipient!.deposit(from: <-self.sentVault)
        }
    }
}
`;

// src/assets/cadence/transactions/main-account/ft/generic_transfer_with_address.cdc
var generic_transfer_with_address_default = `import "FungibleToken"
import "FungibleTokenMetadataViews"

#interaction (
  version: "1.0.0",
	title: "Generic FT Transfer with Contract Address and Name",
	description: "Transfer any Fungible Token by providing the contract address and name",
	language: "en-US",
)

/// Can pass in any contract address and name to transfer a token from that contract
/// This lets you choose the token you want to send
///
/// Any contract can be chosen here, so wallets should check argument values
/// to make sure the intended token contract name and address is passed in
/// Contracts that are used must implement the FTVaultData Metadata View
///
/// Note: This transaction only will work for Fungible Tokens that
///       have their token's resource name set as "Vault".
///       Tokens with other names will need to use a different transaction
///       that additionally specifies the identifier
///
/// @param amount: The amount of tokens to transfer
/// @param to: The address to transfer the tokens to
/// @param contractAddress: The address of the contract that defines the tokens being transferred
/// @param contractName: The name of the contract that defines the tokens being transferred. Ex: "FlowToken"
///
transaction(amount: UFix64, to: Address, contractAddress: Address, contractName: String) {

    // The Vault resource that holds the tokens that are being transferred
    let tempVault: @{FungibleToken.Vault}

    // FTVaultData struct to get paths from
    let vaultData: FungibleTokenMetadataViews.FTVaultData

    prepare(signer: auth(BorrowValue) &Account) {

        // Borrow a reference to the vault stored on the passed account at the passed publicPath
        let resolverRef = getAccount(contractAddress)
            .contracts.borrow<&{FungibleToken}>(name: contractName)
                ?? panic("Could not borrow FungibleToken reference to the contract. Make sure the provided contract name ("
                          .concat(contractName).concat(") and address (").concat(contractAddress.toString()).concat(") are correct!"))

        // Use that reference to retrieve the FTView
        self.vaultData = resolverRef.resolveContractView(resourceType: nil, viewType: Type<FungibleTokenMetadataViews.FTVaultData>()) as! FungibleTokenMetadataViews.FTVaultData?
            ?? panic("Could not resolve FTVaultData view. The ".concat(contractName)
                .concat(" contract needs to implement the FTVaultData Metadata view in order to execute this transaction."))

        // Get a reference to the signer's stored vault
        let vaultRef = signer.storage.borrow<auth(FungibleToken.Withdraw) &{FungibleToken.Provider}>(from: self.vaultData.storagePath)
			?? panic("The signer does not store a FungibleToken.Provider object at the path "
                .concat(self.vaultData.storagePath.toString()).concat("For the ").concat(contractName)
                .concat(" contract at address ").concat(contractAddress.toString())
                .concat(". The signer must initialize their account with this object first!"))

        self.tempVault <- vaultRef.withdraw(amount: amount)

        // Get the string representation of the address without the 0x
        var addressString = contractAddress.toString()
        if addressString.length == 18 {
            addressString = addressString.slice(from: 2, upTo: 18)
        }
        let typeString: String = "A.".concat(addressString).concat(".").concat(contractName).concat(".Vault")
        let type = CompositeType(typeString)
        assert(
            type != nil,
            message: "Could not create a type out of the contract name and address!"
        )

        assert(
            self.tempVault.getType() == type!,
            message: "The Vault that was withdrawn to transfer is not the type that was requested!"
        )
    }

    execute {
        let recipient = getAccount(to)
        let receiverRef = recipient.capabilities.borrow<&{FungibleToken.Receiver}>(self.vaultData.receiverPath)
            ?? panic("Could not borrow a Receiver reference to the FungibleToken Vault in account "
                .concat(to.toString()).concat(" at path ").concat(self.vaultData.receiverPath.toString())
                .concat(". Make sure you are sending to an address that has ")
                .concat("a FungibleToken Vault set up properly at the specified path."))

        // Transfer tokens from the signer's stored vault to the receiver capability
        receiverRef.deposit(from: <-self.tempVault)
    }
}
`;

// src/assets/transaction.defs.ts
var transactions = {
  evmCall: call_default2,
  mainAccountCreateNewWithCOA: create_new_account_with_coa_default,
  mainAccountSetupCOA: setup_coa_default,
  mainEVMTransferERC20: transfer_erc20_default,
  mainFlowTokenDynamicTransfer: dynamic_vm_transfer_default,
  mainFTGenericTransfer: generic_transfer_with_address_default
};

// src/actions/index.ts
var actions_exports = {};
__export(actions_exports, {
  TransferAction: () => TransferAction,
  TransferContent: () => TransferContent
});

// src/actions/transfer.ts
import { z as z2 } from "zod";
import { injectable as injectable6 } from "inversify";
import { elizaLogger as elizaLogger7 } from "@elizaos/core";
import { globalContainer as globalContainer6, property } from "@elizaos-plugins/plugin-di";
function _ts_decorate6(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate6, "_ts_decorate");
function _ts_metadata6(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata6, "_ts_metadata");
var TransferContent = class {
  static {
    __name(this, "TransferContent");
  }
  token;
  amount;
  to;
};
_ts_decorate6([
  property({
    description: "Cadence Resource Identifier or ERC20 contract address (if not native token). this field should be null if the token is native token: $FLOW or FLOW",
    examples: [
      "For Cadence resource identifier, the field should be 'A.1654653399040a61.ContractName'",
      "For ERC20 contract address, the field should be '0xe6ffc15a5bde7dd33c127670ba2b9fcb82db971a'"
    ],
    schema: z2.string().nullable()
  }),
  _ts_metadata6("design:type", Object)
], TransferContent.prototype, "token", void 0);
_ts_decorate6([
  property({
    description: "Amount to transfer, it should be a number or a string",
    examples: [
      "'1000'",
      "1000"
    ],
    schema: z2.union([
      z2.string(),
      z2.number()
    ])
  }),
  _ts_metadata6("design:type", String)
], TransferContent.prototype, "amount", void 0);
_ts_decorate6([
  property({
    description: "Recipient identifier, can a wallet address like EVM address or Cadence address. It should be a string",
    examples: [
      "For Cadence address: '0x1654653399040a61'",
      "For EVM address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e'"
    ],
    schema: z2.string()
  }),
  _ts_metadata6("design:type", String)
], TransferContent.prototype, "to", void 0);
var transferOption = {
  name: "SEND_COIN",
  similes: [
    "SEND_TOKEN",
    "SEND_TOKEN_ON_FLOW",
    "TRANSFER_TOKEN_ON_FLOW",
    "TRANSFER_TOKENS_ON_FLOW",
    "TRANSFER_FLOW",
    "SEND_FLOW",
    "PAY_BY_FLOW"
  ],
  description: "Call this action to transfer any fungible token/coin from the agent's Flow wallet to another address",
  examples: [
    [
      {
        user: "{{user1}}",
        content: {
          text: "Send 1 FLOW to 0xa2de93114bae3e73",
          action: "SEND_COIN"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Send 1 FLOW - A.1654653399040a61.FlowToken to 0xa2de93114bae3e73",
          action: "SEND_COIN"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Send 1000 FROTH - 0xb73bf8e6a4477a952e0338e6cc00cc0ce5ad04ba to 0x000000000000000000000002e44fbfbd00395de5",
          action: "SEND_COIN"
        }
      }
    ]
  ],
  contentClass: TransferContent,
  suppressInitialMessage: true
};
var TransferAction = class extends BaseFlowInjectableAction {
  static {
    __name(this, "TransferAction");
  }
  constructor() {
    super(transferOption);
  }
  /**
   * Validate the transfer action
   * @param runtime the runtime instance
   * @param message the message content
   * @param state the state object
   */
  async validate(runtime, message, state) {
    if (await super.validate(runtime, message, state)) {
      return true;
    }
    return false;
  }
  /**
   * Execute the transfer action
   *
   * @param content the content from processMessages
   * @param callback the callback function to pass the result to Eliza runtime
   * @returns the transaction response
   */
  async execute(content, _runtime, _message, _state, callback) {
    if (!content) {
      elizaLogger7.warn("No content generated");
      return;
    }
    elizaLogger7.log(`Starting ${this.name} handler...`);
    const walletAddress = this.walletSerivce.address;
    const logPrefix = `Account[${walletAddress}/root]`;
    const amount = typeof content.amount === "number" ? content.amount : Number.parseFloat(content.amount);
    const recipient = content.to;
    try {
      let txId;
      let keyIndex;
      if (!content.token) {
        const fromAccountInfo = await this.walletSerivce.getWalletAccountInfo();
        const totalBalance = fromAccountInfo.balance + (fromAccountInfo.coaBalance ?? 0);
        if (totalBalance < amount) {
          throw new Error("Insufficient balance to transfer");
        }
        elizaLogger7.log(`${logPrefix}
 Sending ${amount} FLOW to ${recipient}...`);
        const resp = await this.walletSerivce.sendTransaction(transactions.mainFlowTokenDynamicTransfer, (arg, t) => [
          arg(recipient, t.String),
          arg(amount.toFixed(8), t.UFix64)
        ]);
        txId = resp.txId;
        keyIndex = resp.index;
      } else if (isCadenceIdentifier(content.token)) {
        if (!isFlowAddress(recipient)) {
          throw new Error("Recipient address is not a valid Flow address");
        }
        const [_, tokenAddr, tokenContractName] = content.token.split(".");
        elizaLogger7.log(`${logPrefix}
 Sending ${amount} A.${tokenAddr}.${tokenContractName} to ${recipient}...`);
        const resp = await this.walletSerivce.sendTransaction(transactions.mainFTGenericTransfer, (arg, t) => [
          arg(amount.toFixed(8), t.UFix64),
          arg(recipient, t.Address),
          arg(`0x${tokenAddr}`, t.Address),
          arg(tokenContractName, t.String)
        ]);
        txId = resp.txId;
        keyIndex = resp.index;
      } else if (isEVMAddress(content.token)) {
        if (!isEVMAddress(recipient)) {
          throw new Error("Recipient address is not a valid EVM address");
        }
        elizaLogger7.log(`${logPrefix}
 Sending ${amount} ${content.token}(EVM) to ${recipient}...`);
        const resp = await this.walletSerivce.sendTransaction(transactions.mainEVMTransferERC20, (arg, t) => [
          arg(recipient, t.String),
          arg(amount.toFixed(8), t.UFix64),
          arg(content.token, t.String)
        ]);
        txId = resp.txId;
        keyIndex = resp.index;
      }
      elizaLogger7.log(`${logPrefix}
 Sent transaction: ${txId} by KeyIndex[${keyIndex}]`);
      if (callback) {
        const tokenName = content.token || "FLOW";
        const extraMsg = `${logPrefix}
 Successfully transferred ${content.amount} ${tokenName} to ${content.to}`;
        callback?.({
          text: formatTransationSent(txId, this.walletSerivce.wallet.network, extraMsg),
          content: {
            success: true,
            txid: txId,
            token: content.token,
            to: content.to,
            amount: content.amount
          }
        });
      }
    } catch (e) {
      elizaLogger7.error("Error in sending transaction:", e.message);
      callback?.({
        text: `${logPrefix}
 Unable to process transfer request. Error: 
 ${e.message}`,
        content: {
          error: e.message
        }
      });
    }
    elizaLogger7.log(`Finished ${this.name} handler.`);
  }
};
TransferAction = _ts_decorate6([
  injectable6(),
  _ts_metadata6("design:type", Function),
  _ts_metadata6("design:paramtypes", [])
], TransferAction);
globalContainer6.bind(TransferAction).toSelf();

// src/index.ts
var flowPlugin = {
  name: "flow",
  description: "Flow Plugin for Eliza",
  providers: [
    flowWalletProvider,
    flowConnectorProvider
  ],
  actions: [],
  evaluators: [],
  services: []
};
var index_default = flowPlugin;
export {
  BaseFlowInjectableAction,
  CacheProvider,
  ConnectorProvider,
  FlowConnector,
  FlowWallet,
  FlowWalletService,
  WalletProvider,
  actions_exports as actions,
  cacheProvider,
  index_default as default,
  flowConnectorProvider,
  flowEnvSchema,
  flowPlugin,
  flowWalletProvider,
  formatAgentWalletInfo,
  formatFlowSpent,
  formatTransationSent,
  formatWalletBalances,
  formatWalletCreated,
  formatWalletInfo,
  isCadenceIdentifier,
  isEVMAddress,
  isFlowAddress,
  isScriptQueryResponse,
  isUUID,
  queries_exports as queries,
  scripts,
  symbols_exports as symbols,
  transactions,
  validateFlowConfig
};
//# sourceMappingURL=index.js.map