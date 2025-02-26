import { IAgentRuntime, Character, Provider, ICacheManager, Memory, State, Service, ServiceType, HandlerCallback, Plugin } from '@elizaos/core';
import { z } from 'zod';
import * as fcl from '@onflow/fcl';
import { arg } from '@onflow/fcl';
import * as ftypes from '@onflow/types';
import { Account, TransactionStatus } from '@onflow/typedefs';
import { InjectableProvider, BaseInjectableAction, ActionOptions } from '@elizaos-plugins/plugin-di';
import NodeCache from 'node-cache';

declare const flowEnvSchema: z.ZodObject<{
    FLOW_ADDRESS: z.ZodString;
    FLOW_PRIVATE_KEY: z.ZodString;
    FLOW_NETWORK: z.ZodDefault<z.ZodOptional<z.ZodString>>;
    FLOW_ENDPOINT_URL: z.ZodDefault<z.ZodOptional<z.ZodString>>;
}, "strip", z.ZodTypeAny, {
    FLOW_ADDRESS?: string;
    FLOW_PRIVATE_KEY?: string;
    FLOW_NETWORK?: string;
    FLOW_ENDPOINT_URL?: string;
}, {
    FLOW_ADDRESS?: string;
    FLOW_PRIVATE_KEY?: string;
    FLOW_NETWORK?: string;
    FLOW_ENDPOINT_URL?: string;
}>;
type FlowConfig = z.infer<typeof flowEnvSchema>;
declare function validateFlowConfig(runtime: IAgentRuntime): Promise<FlowConfig>;

interface IFlowScriptExecutor {
    /**
     * Execute a script
     * @param code Cadence code
     * @param args Cadence arguments
     */
    executeScript<T>(code: string, args: fcl.ArgumentFunction, defaultValue: T): Promise<T>;
}
/**
 * Signer interface
 */
interface IFlowSigner {
    /**
     * Send a transaction
     */
    sendTransaction(code: string, args: fcl.ArgumentFunction, authz?: fcl.FclAuthorization): Promise<string>;
    /**
     * Build authorization
     */
    buildAuthorization(accountIndex?: number, privateKey?: string): (acct: Account) => Promise<fcl.AuthZ> | fcl.AuthZ;
}
interface TransactionResponse {
    signer: {
        address: string;
        keyIndex: number;
    };
    txid: string;
}
interface FlowAccountBalanceInfo {
    address: string;
    balance: number;
    coaAddress?: string;
    coaBalance?: number;
}
interface ScriptQueryResponse {
    ok: boolean;
    data?: unknown;
    error?: string | Record<string, unknown>;
    errorMessage?: string;
}
type ArgumentFunction = (argFunc: typeof arg, t: typeof ftypes) => Array<{
    value: unknown;
    xform: unknown;
}>;
type TransactionStatusCallback = (txId: string, status: TransactionStatus, errorMsg?: string) => Promise<void>;
type TransactionCallbacks = {
    onStatusUpdated?: TransactionStatusCallback;
    onFinalized?: TransactionStatusCallback;
    onSealed?: TransactionStatusCallback;
};
type TransactionTrackingPayload = {
    txId: string;
    unsubscribe: () => void;
};
type TransactionSentResponse = {
    txId: string;
    index: number;
};

/**
 * Check if a string is a valid UUID
 * @param str The string to check
 * @returns true if the string is a valid UUID
 */
declare function isUUID(str: string): boolean;
/**
 * Check if an address is a Flow address
 * @param address Address to check
 */
declare function isFlowAddress(address: string): boolean;
/**
 * Check if an address is an EVM address
 * @param address Address to check
 */
declare function isEVMAddress(address: string): boolean;
/**
 * Check if a string is a Cadence identifier
 * @param str String to check
 */
declare function isCadenceIdentifier(str: string): boolean;
/**
 * Check if a string is a Cadence address
 * @param res
 */
declare function isScriptQueryResponse(res: unknown): res is ScriptQueryResponse;

/**
 * Format the agent wallet information
 * @param character
 * @param info
 */
declare function formatAgentWalletInfo(character: Character, info: FlowAccountBalanceInfo): string;
/**
 * Format the account information
 * @param userId user id
 * @param accountName account name
 * @param info flow account information
 * @returns the formatted string
 */
declare function formatWalletInfo(userId: string, accountName: string, info?: FlowAccountBalanceInfo): string;
/**
 * Format the wallet balances
 * @param info
 * @returns
 */
declare function formatWalletBalances(info: FlowAccountBalanceInfo): string;
/**
 * Format the wallet created message
 * @param userId user id
 * @param accountName account name
 * @param newAddress new address
 * @returns the formatted string
 */
declare function formatWalletCreated(userId: string, accountName: string, newAddress: string): string;
/**
 * Format the transaction sent message
 * @param txid
 * @param extra
 */
declare function formatTransationSent(txId: string, network: string, extra?: string): string;
/**
 * Format the FLOW spent message
 * @param fromAddress
 * @param spent
 * @param gasFee
 */
declare function formatFlowSpent(fromAddress: string, spent: number, agentAddr: string, gasFee: number): string;

type NetworkType = "mainnet" | "testnet" | "emulator";
declare class FlowConnector implements IFlowScriptExecutor {
    private readonly flowJSON;
    readonly network: NetworkType;
    private readonly defaultRpcEndpoint;
    /**
     * Initialize the Flow SDK
     */
    constructor(flowJSON: object, network?: NetworkType, defaultRpcEndpoint?: string);
    /**
     * Get the RPC endpoint
     */
    get rpcEndpoint(): string;
    /**
     * Initialize the Flow SDK
     */
    onModuleInit(): Promise<void>;
    /**
     * Ensure the Flow SDK is initialized
     */
    private ensureInited;
    /**
     * Get account information
     */
    getAccount(addr: string): Promise<Account>;
    /**
     * General method of sending transaction
     */
    sendTransaction(code: string, args: fcl.ArgumentFunction, mainAuthz?: fcl.FclAuthorization, extraAuthz?: fcl.FclAuthorization[]): Promise<string>;
    /**
     * Get transaction status
     */
    getTransactionStatus(transactionId: string): Promise<TransactionStatus>;
    /**
     * Get chain id
     */
    getChainId(): Promise<string>;
    /**
     * Send transaction with single authorization
     */
    onceTransactionSealed(transactionId: string): Promise<TransactionStatus>;
    /**
     * Get block object
     * @param blockId
     */
    getBlockHeaderObject(blockId: string): Promise<fcl.BlockHeaderObject>;
    /**
     * Send script
     */
    executeScript<T>(code: string, args: fcl.ArgumentFunction, defaultValue: T): Promise<T>;
}

/**
 * Flow wallet Provider
 */
declare class FlowWallet implements IFlowSigner, IFlowScriptExecutor {
    private readonly connector;
    private readonly cache;
    runtime: IAgentRuntime;
    private readonly privateKeyHex?;
    readonly address: string;
    private account;
    maxKeyIndex: number;
    constructor(runtime: IAgentRuntime, connector: FlowConnector, cache?: NodeCache);
    /**
     * Get the network type
     */
    get network(): NetworkType;
    /**
     * Send a transaction
     * @param code Cadence code
     * @param args Cadence arguments
     */
    sendTransaction(code: string, args: fcl.ArgumentFunction, authz?: fcl.FclAuthorization): Promise<string>;
    /**
     * Execute a script
     * @param code Cadence code
     * @param args Cadence arguments
     */
    executeScript<T>(code: string, args: fcl.ArgumentFunction, defaultValue: T): Promise<T>;
    /**
     * Build authorization
     */
    buildAuthorization(accountIndex?: number, privateKey?: string): (account: Account) => fcl.AuthZ;
    /**
     * Sign a message
     * @param message Message to sign
     */
    signMessage(message: string, privateKey?: string): string;
    /**
     * Sync account info
     */
    syncAccountInfo(): Promise<void>;
    /**
     * Get the wallet balance
     * @returns Wallet balance
     */
    getWalletBalance(forceRefresh?: boolean): Promise<number>;
}

/**
 * Cache provider
 */
declare class CacheProvider implements Provider, InjectableProvider<ICacheManager> {
    private readonly _nodeCache;
    private readonly cacheKey;
    private readonly CACHE_EXPIRY_SEC;
    private readonly providerId;
    private _fileCache;
    /**
     * Initialize the Flow connector provider
     * @param flowJSON The Flow JSON object
     */
    constructor();
    /**
     * Get the cache manager instance
     * @param runtime The runtime object from Eliza framework
     */
    getInstance(runtime: IAgentRuntime): Promise<ICacheManager>;
    /**
     * Eliza provider `get` method
     * @returns The message to be injected into the context
     */
    get(runtime: IAgentRuntime, _message: Memory, _state?: State): Promise<string | null>;
    /**
     * Get cached data
     */
    getCachedData<T>(key: string): Promise<T | null>;
    /**
     * Set cached data in file-based cache
     * @param cacheKey The cache key
     * @param data The data to cache
     * @param ttl The time-to-live in seconds, defaults to 120 seconds, if not provided
     */
    setCachedData<T>(cacheKey: string, data: T, ttl?: number): Promise<void>;
    private _getFileCacheKey;
    private _readFromCache;
    private _writeToCache;
}
declare const cacheProvider: CacheProvider;

/**
 * Connector provider
 */
declare class ConnectorProvider implements Provider, InjectableProvider<FlowConnector> {
    private readonly flowJSON;
    private _connector;
    /**
     * Initialize the Flow connector provider
     * @param flowJSON The Flow JSON object
     */
    constructor(flowJSON: Record<string, unknown>);
    /**
     * Get the Flow connector instance
     * @param runtime The runtime object from Eliza framework
     */
    getInstance(runtime: IAgentRuntime): Promise<FlowConnector>;
    /**
     * Get the connector status
     * @param runtime The runtime object from Eliza framework
     */
    getConnectorStatus(runtime: IAgentRuntime): Promise<string>;
    /**
     * Eliza provider `get` method
     * @returns The message to be injected into the context
     */
    get(runtime: IAgentRuntime, _message: Memory, state?: State): Promise<string | null>;
}
declare const flowConnectorProvider: ConnectorProvider;

/**
 * Wallet provider
 */
declare class WalletProvider implements Provider, InjectableProvider<FlowWallet> {
    private readonly connector;
    private _wallet;
    constructor(connector: ConnectorProvider);
    /**
     * Get the Flow wallet instance
     * @param runtime The runtime object from Eliza framework
     */
    getInstance(runtime: IAgentRuntime): Promise<FlowWallet>;
    /**
     * Eliza provider `get` method
     * @returns The message to be injected into the context
     */
    get(runtime: IAgentRuntime, _message: Memory, state?: State): Promise<string | null>;
}
declare const flowWalletProvider: WalletProvider;

declare module "@elizaos/core" {
    enum ServiceType {
        FLOW_WALLET = "flow-wallet"
    }
}
/**
 * Wallet provider
 */
declare class FlowWalletService extends Service {
    private readonly connectorProvider;
    private readonly walletProvider;
    private static isInitialized;
    private _runtime;
    private _connector;
    private _wallet;
    private _maxKeyIndex;
    private readonly keysInUse;
    private readonly keysTrackingPayloads;
    constructor(connectorProvider: ConnectorProvider, walletProvider: WalletProvider);
    static get serviceType(): ServiceType;
    initialize(runtime: IAgentRuntime): Promise<void>;
    /**
     * Whether the service is initialized or not.
     */
    get isInitialized(): boolean;
    /**
     * Get the Flow connector
     */
    get connector(): FlowConnector;
    /**
     * Get the wallet provider
     */
    get wallet(): FlowWallet;
    /**
     * Get the wallet address
     */
    get address(): string;
    /**
     * Get maximum key index of the wallet
     */
    get maxKeyIndex(): number;
    /**
     * Execute a script with available account key index of the wallet
     * @param code
     * @param argsFunc
     * @param defaultValue
     * @returns
     */
    executeScript<T>(code: string, argsFunc: ArgumentFunction, defaultValue: T): Promise<T>;
    /**
     * Send transction with available account key index of the wallet
     * @param code
     * @param argsFunc
     * @returns
     */
    sendTransaction(code: string, argsFunc: ArgumentFunction, callbacks?: TransactionCallbacks): Promise<TransactionSentResponse>;
    /**
     * Get the wallet account info
     */
    getWalletAccountInfo(): Promise<FlowAccountBalanceInfo>;
    /**
     * Start the service
     */
    private startTransactionTrackingSubstribe;
    /**
     * Acquire and lock an available account key index
     * @returns
     */
    private acquireAndLockIndex;
    /**
     * Acknowledge and unlock an account key index
     * @param index
     */
    private ackAndUnlockIndex;
}

/**
 * Base abstract class for injectable actions
 */
declare abstract class BaseFlowInjectableAction<T> extends BaseInjectableAction<T> {
    walletElizaProvider: WalletProvider;
    walletSerivce: FlowWalletService;
    /**
     * Constructor for the base injectable action
     */
    constructor(opts: ActionOptions<T>);
    /**
     * Abstract method to execute the action
     * @param content The content object
     * @param callback The callback function to pass the result to Eliza runtime
     */
    abstract execute(content: T | null, runtime: IAgentRuntime, message: Memory, state?: State, callback?: HandlerCallback): Promise<unknown | null>;
    /**
     * Default implementation of the validate method
     * You can override this method to add custom validation logic
     *
     * @param runtime The runtime object from Eliza framework
     * @param message The message object from Eliza framework
     * @param state The state object from Eliza framework
     * @returns The validation result
     */
    validate(runtime: IAgentRuntime, _message: Memory, _state?: State): Promise<boolean>;
    /**
     * Default implementation of the preparation of action context
     * You can override this method to add custom logic
     */
    protected prepareActionContext(runtime: IAgentRuntime, message: Memory, state: State): Promise<string>;
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
    handler(runtime: IAgentRuntime, message: Memory, state?: State, options?: Record<string, unknown>, callback?: HandlerCallback): Promise<void>;
}

/**
 * Constant Symbols used in the library
 */
declare const CONSTANTS: {
    FlowJSON: symbol;
};

declare const symbols_CONSTANTS: typeof CONSTANTS;
declare namespace symbols {
  export { symbols_CONSTANTS as CONSTANTS };
}

/**
 * Query the balance of an EVM ERC20 token
 * @param executor
 * @param owner
 * @param evmContractAddress
 */
declare function queryEvmERC20BalanceOf(executor: IFlowScriptExecutor, owner: string, evmContractAddress: string): Promise<bigint>;
/**
 * Query the decimals of an EVM ERC20 token
 * @param executor
 * @param evmContractAddress
 */
declare function queryEvmERC20Decimals(executor: IFlowScriptExecutor, evmContractAddress: string): Promise<number>;
/**
 * Query the total supply of an EVM ERC20 token
 * @param executor
 * @param evmContractAddress
 */
declare function queryEvmERC20TotalSupply(executor: IFlowScriptExecutor, evmContractAddress: string): Promise<bigint>;
/**
 * Query the account info of a Flow address
 * @param executor
 * @param address
 */
declare function queryAccountBalanceInfo(executor: IFlowScriptExecutor, address: string): Promise<FlowAccountBalanceInfo | undefined>;

declare const queries_queryAccountBalanceInfo: typeof queryAccountBalanceInfo;
declare const queries_queryEvmERC20BalanceOf: typeof queryEvmERC20BalanceOf;
declare const queries_queryEvmERC20Decimals: typeof queryEvmERC20Decimals;
declare const queries_queryEvmERC20TotalSupply: typeof queryEvmERC20TotalSupply;
declare namespace queries {
  export { queries_queryAccountBalanceInfo as queryAccountBalanceInfo, queries_queryEvmERC20BalanceOf as queryEvmERC20BalanceOf, queries_queryEvmERC20Decimals as queryEvmERC20Decimals, queries_queryEvmERC20TotalSupply as queryEvmERC20TotalSupply };
}

declare const scripts: {
    evmCall: any;
    evmERC20BalanceOf: any;
    evmERC20GetDecimals: any;
    evmERC20GetTotalSupply: any;
    mainGetAccountInfo: any;
};

declare const transactions: {
    evmCall: any;
    mainAccountCreateNewWithCOA: any;
    mainAccountSetupCOA: any;
    mainEVMTransferERC20: any;
    mainFlowTokenDynamicTransfer: any;
    mainFTGenericTransfer: any;
};

/**
 * The generated content for the transfer action
 */
declare class TransferContent {
    token: string | null;
    amount: string;
    to: string;
}
/**
 * Transfer action
 *
 * @category Actions
 * @description Transfer funds from one account to another
 */
declare class TransferAction extends BaseFlowInjectableAction<TransferContent> {
    constructor();
    /**
     * Validate the transfer action
     * @param runtime the runtime instance
     * @param message the message content
     * @param state the state object
     */
    validate(runtime: IAgentRuntime, message: Memory, state?: State): Promise<boolean>;
    /**
     * Execute the transfer action
     *
     * @param content the content from processMessages
     * @param callback the callback function to pass the result to Eliza runtime
     * @returns the transaction response
     */
    execute(content: TransferContent | null, _runtime: IAgentRuntime, _message: Memory, _state?: State, callback?: HandlerCallback): Promise<void>;
}

type index_TransferAction = TransferAction;
declare const index_TransferAction: typeof TransferAction;
type index_TransferContent = TransferContent;
declare const index_TransferContent: typeof TransferContent;
declare namespace index {
  export { index_TransferAction as TransferAction, index_TransferContent as TransferContent };
}

declare const flowPlugin: Plugin;

export { type ArgumentFunction, BaseFlowInjectableAction, CacheProvider, ConnectorProvider, type FlowAccountBalanceInfo, type FlowConfig, FlowConnector, FlowWallet, FlowWalletService, type IFlowScriptExecutor, type IFlowSigner, type NetworkType, type ScriptQueryResponse, type TransactionCallbacks, type TransactionResponse, type TransactionSentResponse, type TransactionStatusCallback, type TransactionTrackingPayload, WalletProvider, index as actions, cacheProvider, flowPlugin as default, flowConnectorProvider, flowEnvSchema, flowPlugin, flowWalletProvider, formatAgentWalletInfo, formatFlowSpent, formatTransationSent, formatWalletBalances, formatWalletCreated, formatWalletInfo, isCadenceIdentifier, isEVMAddress, isFlowAddress, isScriptQueryResponse, isUUID, queries, scripts, symbols, transactions, validateFlowConfig };
