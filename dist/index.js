var __defProp = Object.defineProperty;
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
      throw new Error(
        `Flow Blockchain configuration validation failed:
${errorMessages}`
      );
    }
    throw error;
  }
}

// src/assets/cadence/scripts/evm/call.cdc?raw
var call_default = 'import "EVM"\n\naccess(all) fun getTypeArray(_ identifiers: [String]): [Type] {\n    var types: [Type] = []\n    for identifier in identifiers {\n        let type = CompositeType(identifier)\n            ?? panic("Invalid identifier: ".concat(identifier))\n        types.append(type)\n    }\n    return types\n}\n\n/// Supports generic calls to EVM contracts that might have return values\n///\naccess(all) fun main(\n    gatewayAddress: Address,\n    evmContractAddressHex: String,\n    calldata: String,\n    gasLimit: UInt64,\n    typeIdentifiers: [String]\n): [AnyStruct] {\n\n    let evmAddress = EVM.addressFromString(evmContractAddressHex)\n\n    let data = calldata.decodeHex()\n\n    let gatewayCOA = getAuthAccount<auth(BorrowValue) &Account>(gatewayAddress)\n        .storage.borrow<auth(EVM.Call) &EVM.CadenceOwnedAccount>(\n            from: /storage/evm\n        ) ?? panic("Could not borrow COA from provided gateway address")\n\n    let evmResult = gatewayCOA.call(\n        to: evmAddress,\n        data: data,\n        gasLimit: gasLimit,\n        value: EVM.Balance(attoflow: 0)\n    )\n\n    return EVM.decodeABI(types: getTypeArray(typeIdentifiers), data: evmResult.data)\n}\n';

// src/assets/cadence/scripts/evm/erc20/balance_of.cdc?raw
var balance_of_default = 'import "EVM"\n\nimport "FlowEVMBridgeUtils"\n\n/// Returns the balance of the owner (hex-encoded EVM address) of a given ERC20 fungible token defined\n/// at the hex-encoded EVM contract address\n///\n/// @param owner: The hex-encoded EVM address of the owner\n/// @param evmContractAddress: The hex-encoded EVM contract address of the ERC20 contract\n///\n/// @return The balance of the address, reverting if the given contract address does not implement the ERC20 method\n///     "balanceOf(address)(uint256)"\n///\naccess(all) fun main(owner: String, evmContractAddress: String): UInt256 {\n    return FlowEVMBridgeUtils.balanceOf(\n        owner: EVM.addressFromString(owner),\n        evmContractAddress: EVM.addressFromString(evmContractAddress)\n    )\n}\n';

// src/assets/cadence/scripts/evm/erc20/get_decimals.cdc?raw
var get_decimals_default = 'import "EVM"\n\nimport "FlowEVMBridgeUtils"\n\naccess(all)\nfun main(erc20ContractAddressHex: String): UInt8 {\n    return FlowEVMBridgeUtils.getTokenDecimals(\n        evmContractAddress: EVM.addressFromString(erc20ContractAddressHex)\n    )\n}\n';

// src/assets/cadence/scripts/evm/erc20/total_supply.cdc?raw
var total_supply_default = 'import "EVM"\n\nimport "FlowEVMBridgeUtils"\n\n/// Retrieves the total supply of the ERC20 contract at the given EVM contract address. Reverts on EVM call failure.\n///\n/// @param evmContractAddress: The EVM contract address to retrieve the total supply from\n///\n/// @return the total supply of the ERC20\n///\naccess(all) fun main(evmContractAddressHex: String): UInt256 {\n    return FlowEVMBridgeUtils.totalSupply(\n        evmContractAddress: EVM.addressFromString(evmContractAddressHex)\n    )\n}\n';

// src/assets/cadence/scripts/main-account/get_acct_info.cdc?raw
var get_acct_info_default = 'import "FungibleToken"\nimport "EVM"\n\n/// Returns the hex encoded address of the COA in the given Flow address\n///\naccess(all) fun main(flowAddress: Address): AccountInfo {\n    var flowBalance: UFix64 = 0.0\n    if let flowVaultRef = getAccount(flowAddress)\n        .capabilities.get<&{FungibleToken.Balance}>(/public/flowTokenBalance)\n        .borrow() {\n        flowBalance = flowVaultRef.balance\n    }\n\n    var coaAddress: String? = nil\n    var coaBalance: UFix64? = nil\n\n    if let address: EVM.EVMAddress = getAuthAccount<auth(BorrowValue) &Account>(flowAddress)\n        .storage.borrow<&EVM.CadenceOwnedAccount>(from: /storage/evm)?.address() {\n        let bytes: [UInt8] = []\n        for byte in address.bytes {\n            bytes.append(byte)\n        }\n        coaAddress = String.encodeHex(bytes)\n        coaBalance = address.balance().inFLOW()\n    }\n    return AccountInfo(\n        flowAddress,\n        flowBalance,\n        coaAddress,\n        coaBalance\n    )\n}\n\naccess(all) struct AccountInfo {\n    access(all) let address: Address\n    access(all) let balance: UFix64\n    access(all) let coaAddress: String?\n    access(all) let coaBalance: UFix64?\n\n    init(\n        _ address: Address,\n        _ balance: UFix64,\n        _ coaAddress: String?,\n        _ coaBalance: UFix64?\n    ) {\n        self.address = address\n        self.balance = balance\n        self.coaAddress = coaAddress\n        self.coaBalance = coaBalance\n    }\n}\n';

// src/assets/script.defs.ts
var scripts = {
  evmCall: call_default,
  evmERC20BalanceOf: balance_of_default,
  evmERC20GetDecimals: get_decimals_default,
  evmERC20GetTotalSupply: total_supply_default,
  mainGetAccountInfo: get_acct_info_default
};

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

// src/queries.ts
var queries_exports = {};
__export(queries_exports, {
  queryAccountBalanceInfo: () => queryAccountBalanceInfo,
  queryEvmERC20BalanceOf: () => queryEvmERC20BalanceOf,
  queryEvmERC20Decimals: () => queryEvmERC20Decimals,
  queryEvmERC20TotalSupply: () => queryEvmERC20TotalSupply
});
async function queryEvmERC20BalanceOf(executor, owner, evmContractAddress) {
  const ret = await executor.executeScript(
    scripts.evmERC20BalanceOf,
    (arg, t) => [arg(owner, t.String), arg(evmContractAddress, t.String)],
    BigInt(0)
  );
  return BigInt(ret);
}
async function queryEvmERC20Decimals(executor, evmContractAddress) {
  const ret = await executor.executeScript(
    scripts.evmERC20GetDecimals,
    (arg, t) => [arg(evmContractAddress, t.String)],
    "0"
  );
  return parseInt(ret);
}
async function queryEvmERC20TotalSupply(executor, evmContractAddress) {
  const ret = await executor.executeScript(
    scripts.evmERC20GetTotalSupply,
    (arg, t) => [arg(evmContractAddress, t.String)],
    BigInt(0)
  );
  return BigInt(ret);
}
async function queryAccountBalanceInfo(executor, address) {
  const ret = await executor.executeScript(
    scripts.mainGetAccountInfo,
    (arg, t) => [arg(address, t.Address)],
    void 0
  );
  if (!ret) {
    return void 0;
  }
  return {
    address: ret.address,
    balance: parseFloat(ret.balance),
    coaAddress: ret.coaAddress,
    coaBalance: ret.coaBalance ? parseFloat(ret.coaBalance) : void 0
  };
}

// src/providers/connector.provider.ts
import {
  elizaLogger
} from "@elizaos/core";

// src/providers/utils/flow.connector.ts
import * as fcl from "@onflow/fcl";

// src/types/exception.ts
var Exception = class extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.code = code;
  }
};

// src/providers/utils/flow.connector.ts
var isGloballyInited = false;
var globallyPromise = null;
var FlowConnector = class {
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
        throw new Exception(
          5e4,
          `Network type ${this.network} is not supported`
        );
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
    await cfg.load({ flowJSON: this.flowJSON });
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
    return await fcl.send([fcl.getAccount(addr)]).then(fcl.decode);
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
        authorizations: (extraAuthz?.length ?? 0) === 0 ? [mainAuthz] : [mainAuthz, ...extraAuthz]
      });
    } else {
      return await fcl.mutate({
        cadence: code,
        args
      });
    }
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
    return await fcl.send([fcl.getBlockHeader(), fcl.atBlockId(blockId)]).then(fcl.decode);
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

// src/providers/connector.provider.ts
var _instance;
async function _getDefaultConnectorInstance(runtime) {
  if (!_instance) {
    _instance = await _createFlowConnector(runtime, flow_default);
  }
  return _instance;
}
async function _createFlowConnector(runtime, flowJSON) {
  const rpcEndpoint = runtime.getSetting("FLOW_ENDPOINT_URL");
  const network = runtime.getSetting("FLOW_NETWORK");
  const instance = new flow_connector_default(flowJSON, network, rpcEndpoint);
  await instance.onModuleInit();
  return instance;
}
async function getFlowConnectorInstance(runtime, inputedFlowJSON = void 0) {
  let connector;
  if (inputedFlowJSON && typeof inputedFlowJSON === "object" && typeof inputedFlowJSON?.networks === "object" && typeof inputedFlowJSON?.dependencies === "object") {
    connector = await _createFlowConnector(runtime, inputedFlowJSON);
  } else {
    connector = await _getDefaultConnectorInstance(runtime);
  }
  return connector;
}
var FlowConnectorProvider = class {
  constructor(instance) {
    this.instance = instance;
  }
  getConnectorStatus(runtime) {
    let output = `Now user<${runtime.character.name}> connected to
`;
    output += `Flow network: ${this.instance.network}
`;
    output += `Flow Endpoint: ${this.instance.rpcEndpoint}
`;
    return output;
  }
  // async getFormattedPortfolio(_runtime: IAgentRuntime): Promise<string> {
  //     return Promise.resolve(this.getConnectorStatus(_runtime));
  // }
};
var flowConnectorProvider = {
  get: async (runtime, _message, _state) => {
    try {
      const provider = new FlowConnectorProvider(
        await getFlowConnectorInstance(runtime)
      );
      return provider.getConnectorStatus(runtime);
    } catch (error) {
      elizaLogger.error(
        "Error in Flow connector provider:",
        error.message
      );
      return null;
    }
  }
};

// src/providers/wallet.provider.ts
import {
  elizaLogger as elizaLogger2
} from "@elizaos/core";
import NodeCache from "node-cache";
import * as fcl2 from "@onflow/fcl";

// src/providers/utils/pure.signer.ts
import elliptic from "elliptic";
import { SHA3 } from "sha3";
var PureSigner = class {
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
    return Buffer.concat([r.valueOf(), s.valueOf()]).toString("hex");
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

// src/providers/wallet.provider.ts
var FlowWalletProvider = class {
  constructor(runtime, connector, cache = new NodeCache({ stdTTL: 300 })) {
    this.connector = connector;
    this.cache = cache;
    this.address = getSignerAddress(runtime);
    this.runtime = runtime;
    const privateKey = runtime.getSetting("FLOW_PRIVATE_KEY");
    if (!privateKey) {
      elizaLogger2.warn(
        `The default Flow wallet ${this.address} has no private key`
      );
    } else {
      this.privateKeyHex = privateKey.startsWith("0x") ? privateKey.slice(2) : privateKey;
    }
  }
  runtime;
  privateKeyHex;
  address;
  // Runtime data
  account = null;
  maxKeyIndex = 0;
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
    return await this.connector.sendTransaction(
      code,
      args,
      authz ?? this.buildAuthorization()
    );
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
        tempId: `${address}-${accountIndex}`,
        addr: fcl2.sansPrefix(address),
        keyId: Number(accountIndex),
        signingFunction: (signable) => {
          return Promise.resolve({
            f_type: "CompositeSignature",
            f_vsn: "1.0.0",
            addr: fcl2.withPrefix(address),
            keyId: Number(accountIndex),
            signature: this.signMessage(
              signable.message,
              privateKey
            )
          });
        }
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
    elizaLogger2.debug("Flow account info synced", {
      address: this.address,
      balance: this.account.balance,
      maxKeyIndex: this.maxKeyIndex,
      keys: this.account.keys
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
  /**
   * Query the balance of this wallet
   */
  async queryAccountBalanceInfo() {
    return await queryAccountBalanceInfo(this, this.address);
  }
};
function isFlowAddress(address) {
  const regExp = /^0x[a-fA-F0-9]{16}$/gi;
  return regExp.test(address);
}
function isEVMAddress(address) {
  const regExp = /^0x[a-fA-F0-9]{40}$/gi;
  return regExp.test(address);
}
function isCadenceIdentifier(str) {
  const cadenceIdentifier = /^A\.[0-9a-fA-F]{16}\.[0-9a-zA-Z_]+/;
  return cadenceIdentifier.test(str);
}
function getSignerAddress(runtime) {
  const signerAddr = runtime.getSetting("FLOW_ADDRESS");
  if (!signerAddr) {
    elizaLogger2.error("No signer address");
    throw new Exception(50200, "No signer info");
  }
  return signerAddr;
}
var flowWalletProvider = {
  get: async (runtime, _message, _state) => {
    if (!runtime.getSetting("FLOW_ADDRESS") || !runtime.getSetting("FLOW_PRIVATE_KEY")) {
      elizaLogger2.error(
        "FLOW_ADDRESS or FLOW_PRIVATE_KEY not configured, skipping wallet injection"
      );
      return null;
    }
    try {
      const connector = await getFlowConnectorInstance(runtime);
      const walletProvider = new FlowWalletProvider(runtime, connector);
      const info = await walletProvider.queryAccountBalanceInfo();
      if (!info || info?.address !== walletProvider.address) {
        elizaLogger2.error("Invalid account info");
        return null;
      }
      let output = `Here is user<${runtime.character.name}>'s wallet status:
`;
      output += `Flow wallet address: ${walletProvider.address}
`;
      output += `FLOW balance: ${info.balance} FLOW
`;
      output += `Flow wallet's COA(EVM) address: ${info.coaAddress || "unknown"}
`;
      output += `FLOW balance in COA(EVM) address: ${info.coaBalance ?? 0} FLOW`;
      return output;
    } catch (error) {
      elizaLogger2.error("Error in Flow wallet provider:", error.message);
      return null;
    }
  }
};

// src/actions/transfer.ts
import {
  composeContext,
  elizaLogger as elizaLogger3,
  generateObjectArray,
  ModelClass
} from "@elizaos/core";

// src/templates/index.ts
var transferTemplate = `Given the recent messages and wallet information below:

{{recentMessages}}

{{walletInfo}}

Extract the following information about the requested transfer:
- Field "token": Cadence Resource Identifier or ERC20 contract address (if not native token). this field should be null if the token is native token: $FLOW or FLOW. Examples for this field:
    1. For Cadence resource identifier, the field should be "A.1654653399040a61.ContractName"
    2. For ERC20 contract address, the field should be "0xe6ffc15a5bde7dd33c127670ba2b9fcb82db971a"
- Field "amount": Amount to transfer, it should be a number or a string. Examples for this field:
    1. "1000"
    2. 1000
- Field "to": Recipient wallet address, can be EVM address or Cadence address. Examples for this field:
    1. Cadence address: "0x1654653399040a61"
    2. EVM address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
- Field "matched": Boolean value indicating if field "token" matches the field "to" or not. Here is the rules:
    1. if field "token" is "null" or Cadence resource identifier, field "to" can be EVM address or Cadence address, so the value of "matched" should be true.
    2. if field "token" is ERC20 contract address, field "to" should be EVM address, so the value of "matched" should be true, otherwise false.

Respond with a JSON markdown block containing only the extracted values. Use null for any values that cannot be determined:

\`\`\`json
{
    "token": string | null
    "amount": number | string | null,
    "to": string | null,
    "matched": boolean
}
\`\`\`
`;

// src/actions/transfer.ts
function isTransferContent(runtime, content) {
  elizaLogger3.log("Content for transfer", content);
  return (!content.token || typeof content.token === "string" && (isCadenceIdentifier(content.token) || isEVMAddress(content.token))) && typeof content.to === "string" && (isEVMAddress(content.to) || isFlowAddress(content.to)) && (typeof content.amount === "string" || typeof content.amount === "number") && typeof content.matched === "boolean";
}
var USE_KEY_INDEX = 0;
var TransferAction = class {
  constructor(walletProvider, useKeyIndex = USE_KEY_INDEX) {
    this.walletProvider = walletProvider;
    this.useKeyIndex = useKeyIndex;
  }
  /**
   * Process the messages and generate the transfer content
   */
  async processMessages(runtime, message, state) {
    if (!state) {
      state = await runtime.composeState(message);
    } else {
      state = await runtime.updateRecentMessageState(state);
    }
    const transferContext = composeContext({
      state,
      template: transferTemplate
    });
    const recommendations = await generateObjectArray({
      runtime,
      context: transferContext,
      modelClass: ModelClass.MEDIUM
    });
    elizaLogger3.debug("Recommendations", recommendations);
    const content = recommendations[recommendations.length - 1];
    if (!isTransferContent(runtime, content)) {
      elizaLogger3.error("Invalid content for SEND_COIN action.");
      throw new Exception(50100, "Invalid transfer content");
    }
    if (!content.matched) {
      elizaLogger3.error("Content does not match the transfer template.");
      throw new Exception(
        50100,
        "Content does not match the transfer template"
      );
    }
    return content;
  }
  async transfer(content, callback) {
    elizaLogger3.log("Starting Flow Plugin's SEND_COIN handler...");
    const resp = {
      signer: {
        address: this.walletProvider.address,
        keyIndex: this.useKeyIndex
      },
      txid: ""
    };
    const logPrefix = `Address: ${resp.signer.address}, using keyIdex: ${resp.signer.keyIndex}
`;
    const recipient = content.to;
    const amount = typeof content.amount === "number" ? content.amount : parseFloat(content.amount);
    const accountInfo = await queryAccountBalanceInfo(
      this.walletProvider,
      this.walletProvider.address
    );
    const totalBalance = accountInfo.balance + (accountInfo.coaBalance ?? 0);
    if (totalBalance < amount) {
      elizaLogger3.error("Insufficient balance to transfer.");
      if (callback) {
        callback({
          text: `${logPrefix} Unable to process transfer request. Insufficient balance.`,
          content: {
            error: "Insufficient balance"
          }
        });
      }
      throw new Exception(50100, "Insufficient balance to transfer");
    }
    try {
      const authz = this.walletProvider.buildAuthorization(
        this.useKeyIndex
      );
      if (!content.token) {
        elizaLogger3.log(
          `${logPrefix} Sending ${amount} FLOW to ${recipient}...`
        );
        resp.txid = await this.walletProvider.sendTransaction(
          transactions.mainFlowTokenDynamicTransfer,
          (arg, t) => [
            arg(recipient, t.String),
            arg(amount.toFixed(1), t.UFix64)
          ],
          authz
        );
      } else if (isCadenceIdentifier(content.token)) {
        const [_, tokenAddr, tokenContractName] = content.token.split(".");
        elizaLogger3.log(
          `${logPrefix} Sending ${amount} A.${tokenAddr}.${tokenContractName} to ${recipient}...`
        );
        resp.txid = await this.walletProvider.sendTransaction(
          transactions.mainFTGenericTransfer,
          (arg, t) => [
            arg(amount.toFixed(1), t.UFix64),
            arg(recipient, t.Address),
            arg("0x" + tokenAddr, t.Address),
            arg(tokenContractName, t.String)
          ],
          authz
        );
      } else if (isEVMAddress(content.token)) {
        const decimals = await queryEvmERC20Decimals(
          this.walletProvider,
          content.token
        );
        const adjustedAmount = BigInt(amount * Math.pow(10, decimals));
        elizaLogger3.log(
          `${logPrefix} Sending ${adjustedAmount} ${content.token}(EVM) to ${recipient}...`
        );
        resp.txid = await this.walletProvider.sendTransaction(
          transactions.mainEVMTransferERC20,
          (arg, t) => [
            arg(content.token, t.String),
            arg(recipient, t.String),
            // Convert the amount to string, the string should be pure number, not a scientific notation
            arg(adjustedAmount.toString(), t.UInt256)
          ],
          authz
        );
      }
      elizaLogger3.log(`${logPrefix} Sent transaction: ${resp.txid}`);
      if (callback) {
        const tokenName = content.token || "FLOW";
        const baseUrl = this.walletProvider.network === "testnet" ? "https://testnet.flowscan.io" : "https://flowscan.io";
        const txURL = `${baseUrl}/tx/${resp.txid}/events`;
        callback({
          text: `${logPrefix} Successfully transferred ${content.amount} ${tokenName} to ${content.to}
Transaction: [${resp.txid}](${txURL})`,
          content: {
            success: true,
            txid: resp.txid,
            token: content.token,
            to: content.to,
            amount: content.amount
          }
        });
      }
    } catch (e) {
      elizaLogger3.error("Error in sending transaction:", e.message);
      if (callback) {
        callback({
          text: `${logPrefix} Unable to process transfer request. Error in sending transaction.`,
          content: {
            error: e.message
          }
        });
      }
      if (e instanceof Exception) {
        throw e;
      } else {
        throw new Exception(
          50100,
          "Error in sending transaction: " + e.message
        );
      }
    }
    elizaLogger3.log("Completed Flow Plugin's SEND_COIN handler.");
    return resp;
  }
};
var transferAction = {
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
  validate: async (runtime, _message) => {
    await validateFlowConfig(runtime);
    const flowConnector = await getFlowConnectorInstance(runtime);
    const walletProvider = new FlowWalletProvider(runtime, flowConnector);
    try {
      await walletProvider.syncAccountInfo();
    } catch {
      elizaLogger3.error("Failed to sync account info");
      return false;
    }
    return true;
  },
  handler: async (runtime, message, state, _options, callback) => {
    const flowConnector = await getFlowConnectorInstance(runtime);
    const walletProvider = new FlowWalletProvider(runtime, flowConnector);
    const action = new TransferAction(walletProvider);
    let content;
    try {
      content = await action.processMessages(runtime, message, state);
    } catch (err) {
      elizaLogger3.error("Error in processing messages:", err.message);
      if (callback) {
        callback({
          text: "Unable to process transfer request. Invalid content: " + err.message,
          content: {
            error: "Invalid content"
          }
        });
      }
      return false;
    }
    try {
      const res = await action.transfer(content, callback);
      elizaLogger3.log(
        `Transfer action response: ${res.signer.address}[${res.signer.keyIndex}] - ${res.txid}`
      );
    } catch {
      return false;
    }
    return true;
  },
  examples: [
    [
      {
        user: "{{user1}}",
        content: {
          text: "Send 1 FLOW to 0xa2de93114bae3e73"
        }
      },
      {
        user: "{{user2}}",
        content: {
          text: "Sending 1 FLOW tokens now, pls wait...",
          action: "SEND_COIN"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Send 1 FLOW - A.1654653399040a61.FlowToken to 0xa2de93114bae3e73"
        }
      },
      {
        user: "{{user2}}",
        content: {
          text: "Sending 1 FLOW tokens now, pls wait...",
          action: "SEND_COIN"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Send 1000 FROTH - 0xb73bf8e6a4477a952e0338e6cc00cc0ce5ad04ba to 0x000000000000000000000002e44fbfbd00395de5"
        }
      },
      {
        user: "{{user2}}",
        content: {
          text: "Sending 1000 FROTH tokens now, pls wait...",
          action: "SEND_COIN"
        }
      }
    ]
  ]
};

// src/index.ts
var flowPlugin = {
  name: "flow",
  description: "Flow Plugin for Eliza",
  providers: [flowWalletProvider, flowConnectorProvider],
  actions: [transferAction],
  evaluators: [],
  services: []
};
var index_default = flowPlugin;
export {
  flow_connector_default as FlowConnector,
  FlowConnectorProvider,
  FlowWalletProvider,
  index_default as default,
  flowConnectorProvider,
  flowEnvSchema,
  flowPlugin,
  flowWalletProvider,
  getFlowConnectorInstance,
  isCadenceIdentifier,
  isEVMAddress,
  isFlowAddress,
  queries_exports as queries,
  scripts,
  transactions,
  validateFlowConfig
};
//# sourceMappingURL=index.js.map