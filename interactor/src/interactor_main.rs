#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

mod proxy;

use clap::builder::Str;
use multiversx_sc_snippets::{imports::*, sdk::data::address};
use multiversx_sc_snippets::multiversx_sc_scenario::api::VMHooksApi;
use multiversx_sc_snippets::sdk;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
};

const GATEWAY: &str = sdk::gateway::DEVNET_GATEWAY;
// const GATEWAY: &str = "http://localhost:8085";



const STATE_FILE: &str = "state.toml";
const WALLET_ADDRESS: &str = "erd1tjkfemhpxmch4vx306y85x2lv2n9d6hvn8qpe6atc7m82wef75pqmnws0t";

#[tokio::main]
async fn main() {
    // env_logger::init();

    // let mut args = std::env::args();
    // let _ = args.next();
    // let cmd = args.next().expect("at least one argument required");
    // let mut interact = ContractInteract::new().await;
    // match cmd.as_str() {
    //     "deploy" => interact.deploy().await,
    //     "upgrade" => interact.upgrade().await,
    //     "set_unbond_period" => interact.set_unbond_period().await,
    //     "whitelist_token" => interact.whitelist_token().await,
    //     "blacklist_token" => interact.blacklist_token().await,
    //     "lock" => interact.lock().await,
    //     "unlock" => interact.unlock().await,
    //     "unbond" => interact.unbond().await,
    //     "lockedTokenAmounts" => interact.locked_token_amounts_by_address().await,
    //     "unlockedTokenAmounts" => interact.unlocked_token_by_address().await,
    //     "lockedTokens" => interact.locked_tokens().await,
    //     "unlockedTokens" => interact.unlocked_tokens().await,
    //     "whitelistedTokens" => interact.token_whitelist().await,
    //     "unbondPeriod" => interact.unbond_period().await,
    //     _ => panic!("unknown command: {}", &cmd),
    // }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    contract_address: Option<Bech32Address>,
}

impl State {
    // Deserializes state from file
    pub fn load_state() -> Self {
        if Path::new(STATE_FILE).exists() {
            let mut file = std::fs::File::open(STATE_FILE).unwrap();
            let mut content = String::new();
            file.read_to_string(&mut content).unwrap();
            toml::from_str(&content).unwrap()
        } else {
            Self::default()
        }
    }

    /// Sets the contract address
    pub fn set_address(&mut self, address: Bech32Address) {
        self.contract_address = Some(address);
    }

    /// Returns the contract address
    pub fn current_address(&self) -> &Bech32Address {
        self.contract_address
            .as_ref()
            .expect("no known contract, deploy first")
    }
}

impl Drop for State {
    // Serializes state to file
    fn drop(&mut self) {
        let mut file = std::fs::File::create(STATE_FILE).unwrap();
        file.write_all(toml::to_string(self).unwrap().as_bytes())
            .unwrap();
    }
}

struct TokenPayments {
    token_ids: Vec<String>,
    token_nonces: Vec<u64>,
    token_amounts: Vec<u128>,
}

impl TokenPayments {
    fn new() -> Self {
        TokenPayments {
            token_ids: Vec::new(),
            token_nonces: Vec::new(),
            token_amounts: Vec::new(),
        }
    }

    fn add(&mut self, token_id: String, token_nonce: u64, token_amount: u128) {
        self.token_ids.push(token_id);
        self.token_nonces.push(token_nonce);
        self.token_amounts.push(token_amount);
    }
}

struct ContractInteract {
    interactor: Interactor,
    wallet_address: Address,
    contract_code: BytesValue,
    state: State,
}

impl ContractInteract {
    async fn new() -> Self {
        let mut interactor = Interactor::new(GATEWAY).await;
        let wallet_address =
            interactor.register_wallet(Wallet::from_pem_file("../ctfBlac.pem").unwrap());

        let contract_code = BytesValue::interpret_from(
            "mxsc:../output/liquid-locking.mxsc.json",
            &InterpreterContext::default(),
        );

        ContractInteract {
            interactor,
            wallet_address,
            contract_code,
            state: State::load_state(),
        }
    }

    async fn deploy(&mut self, unbond_period: u64) {
        let unbond_period = 1u64;

        let new_address = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .gas(35_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .init(unbond_period)
            .code(&self.contract_code)
            .returns(ReturnsNewAddress)
            .prepare_async()
            .run()
            .await;
        let new_address_bech32 = bech32::encode(&new_address);
        self.state.set_address(Bech32Address::from_bech32_string(
            new_address_bech32.clone(),
        ));

        println!("new address: {new_address_bech32}");
    }

    async fn upgrade(&mut self, unbond_period: u64) {
        let state_address = self.state.current_address();

        println!("State_address {state_address:?}");

        let response = self
            .interactor
            .tx()
            .to(state_address)
            .from(&self.wallet_address)
            .gas(35_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .upgrade(unbond_period)
            .code(&self.contract_code)
            .code_metadata(CodeMetadata::UPGRADEABLE)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn set_unbond_period(&mut self, unbond_period: u64) {
        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(35_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .set_unbond_period(unbond_period)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn whitelist_token(&mut self, token: &str) {
        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(3_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .whitelist_token(TokenIdentifier::from(token))
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn blacklist_token(&mut self, token: &str) {
        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(30_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .blacklist_token(TokenIdentifier::from(token))
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn lock(&mut self, tokens: TokenPayments, expected_error:ExpectError<'_>) {

        let mut tokenPayments = ManagedVec::new();

        for i in 0..tokens.token_ids.len() {
            let aux = EsdtTokenPayment::new(
                TokenIdentifier::from(&tokens.token_ids[i].to_string()),
                tokens.token_nonces[i],
                BigUint::from(tokens.token_amounts[i]),
            );

            tokenPayments.push(aux);
        }

        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(30_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .lock()
            .payment(tokenPayments)
            .returns(expected_error)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn unlock(&mut self, tokens: TokenPayments) {

        let mut tokenPayments = ManagedVec::new();

        for i in 0..tokens.token_ids.len() {
            let aux = EsdtTokenPayment::new(
                TokenIdentifier::from(&tokens.token_ids[i].to_string()),
                tokens.token_nonces[i],
                BigUint::from(tokens.token_amounts[i]),
            );

            tokenPayments.push(aux);
        }

        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(30_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .unlock(tokenPayments)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn unbond(&mut self, token_id: &str) {
        let tokens = ManagedVec::from_single_item(TokenIdentifier::from(token_id));

        let response = self
            .interactor
            .tx()
            .from(&self.wallet_address)
            .to(self.state.current_address())
            .gas(40_000_000u64)
            .typed(proxy::LiquidLockingProxy)
            .unbond(tokens)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {response:?}");
    }

    async fn locked_token_amounts_by_address(&mut self, address: &Address) {

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .locked_token_amounts_by_address(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn unlocked_token_by_address(&mut self, address: &Address) {

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unlocked_token_by_address(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn locked_tokens(&mut self) {
        let address = &self.wallet_address;

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .locked_tokens(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn unlocked_tokens(&mut self) {
        let address = &self.wallet_address;

        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unlocked_tokens(address)
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn token_whitelist(&mut self) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .token_whitelist()
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn unbond_period(&mut self) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unbond_period()
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }

    async fn unlocked_token_epochs(&mut self, address: &Address, token: &str) {
        let result_value = self
            .interactor
            .query()
            .to(self.state.current_address())
            .typed(proxy::LiquidLockingProxy)
            .unlocked_token_epochs(address, TokenIdentifier::from(token))
            .returns(ReturnsResultUnmanaged)
            .prepare_async()
            .run()
            .await;

        println!("Result: {result_value:?}");
    }
}


// ---------------------------------- TESTING THE SC ---------------------------------------------------------------


fn denominate_value(input: u128) -> u128 {
    input * 10u128.pow(18)
}

fn address_from_str(input: &str) -> Address {
    let address = bech32::decode(input);
    address
}

#[tokio::test]
async fn test_deploy() {
    let mut contract_interactor = ContractInteract::new().await;

    contract_interactor.deploy(0).await;
}

// SCENARIO 1 - Test the LOCK endpoint
// User tries to lock an ESDT payments vector

//Fail - Message: no payment provided (payments vector is empty)
#[tokio::test]
async fn test_payments_empty() {
    let mut interactor = ContractInteract::new().await;

    let payments = TokenPayments::new();

    interactor.lock(payments, ExpectError(4, "no payment provided")).await;
}

//Fail - Message: invalid token provided (provided an NFT, with nonce != 0)
#[tokio::test]
async fn test_payments_invalid_token() {
    let mut interactor = ContractInteract::new().await;

    let mut payments = TokenPayments::new();
    payments.add(String::from("IULNFT-4754fc"), 1u64, 1u128);

    interactor.lock(payments, ExpectError(4, "invalid token provided")).await;
}

//Fail - Message: amount must be greater than 0
#[tokio::test]
async fn test_payments_amount_zero() {
    let mut interactor = ContractInteract::new().await;
    interactor.whitelist_token("IULTKN20-91acfb").await;

    let mut payments = TokenPayments::new();
    payments.add(String::from("IULTKN20-91acfb"), 0u64, denominate_value(0));

    interactor.lock(payments, ExpectError(4, "amount must be greater than 0")).await;
}

//Fail - Message: token is not whitelisted
#[tokio::test]
async fn test_payments_token_not_whitelisted() {
    let mut interactor = ContractInteract::new().await;
    interactor.blacklist_token("IULTKN20-91acfb").await;

    let mut payments = TokenPayments::new();
    payments.add(String::from("IULTKN20-91acfb"), 0u64, denominate_value(10));

    interactor.lock(payments, ExpectError(4, "token is not whitelisted")).await;
}

// Successful - Happy path 
#[tokio::test]
async fn test_lock_successful() {
    let mut interactor = ContractInteract::new().await;

    interactor.whitelist_token("IULTKN20-91acfb").await;
    interactor.whitelist_token("IULTKN30-9e0f5a").await;

    print!("\n\n----------BEFORE----------");
    print!("\n\nVIEW INTO LOCKED_TOKEN_AMOUNTS: \n");
    interactor.locked_token_amounts_by_address(&address_from_str(WALLET_ADDRESS)).await;

    print!("\n\nVIEW INTO LOCKED_TOKENS: \n");
    interactor.locked_tokens().await;

    let mut payments = TokenPayments::new();
    payments.add(String::from("IULTKN20-91acfb"), 0u64, denominate_value(10));
    payments.add(String::from("IULTKN30-9e0f5a"), 0u64, denominate_value(30));
    
    interactor.lock(payments, ExpectError(0, "")).await;

    print!("\n\n----------AFTER----------");
    print!("\n\nVIEW INTO LOCKED_TOKEN_AMOUNTS: \n");
    interactor.locked_token_amounts_by_address(&address_from_str(WALLET_ADDRESS)).await;

    print!("\n\nVIEW INTO LOCKED_TOKENS: \n");
    interactor.locked_tokens().await;

}


#[tokio::test]
async fn test_insuficient_funds_lock() {
    let mut interactor = ContractInteract::new().await;

    interactor.whitelist_token("ITKN-d3deee").await;

    let mut payments = TokenPayments::new();
    payments.add(String::from("ITKN-d3deee"), 0u64, denominate_value(5));
    
    interactor.lock(payments, ExpectError(0, "")).await;

}



#[tokio::test]
async fn test_unlock_successful() {
    let mut interactor = ContractInteract::new().await;

    let mut payments = TokenPayments::new();
    payments.add(String::from("IULTKN20-91acfb"), 0u64, denominate_value(10));

   interactor.unlock(payments).await;

   print!("\n\nView into unlocked_token_amounts: \n");
   interactor.unlocked_token_by_address(&address_from_str(WALLET_ADDRESS)).await;
}

#[tokio::test]
async fn test_unbond() {
    let mut interactor = ContractInteract::new().await;

    interactor.unbond("IULTKN20-91acfb").await;
    // 10
}


#[tokio::test]
async fn test_blacklist_token() {
    let mut interactor = ContractInteract::new().await;

    interactor.whitelist_token("IULTKN20-91acfb").await;
    interactor.token_whitelist().await;

    interactor.blacklist_token("IULTKN20-91acfb").await;
    interactor.token_whitelist().await;
}





