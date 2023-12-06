use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use eth_trie_utils::nibbles::Nibbles;
use eth_trie_utils::partial_trie::{HashedPartialTrie, PartialTrie};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use hex_literal::hex;
use keccak_hash::keccak;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::KeccakGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use plonky2_evm::all_stark::AllStark;
use plonky2_evm::config::StarkConfig;
use plonky2_evm::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use plonky2_evm::generation::{GenerationInputs, TrieInputs};
use plonky2_evm::proof::{BlockHashes, BlockMetadata, TrieRoots};
use plonky2_evm::prover::prove;
use plonky2_evm::verifier::verify_proof;
use plonky2_evm::Node;

type F = GoldilocksField;
const D: usize = 2;
type C = KeccakGoldilocksConfig;

/// Test a simple token transfer to a new address.
#[test]
fn test_simple_transfer() -> anyhow::Result<()> {
    init_logger();
  
    // 初期設定
    // stark関連のスタンダードな設定をここで行う。
    // snarkと違い、starkは大量のデータや複雑な計算に対しても効率的に動作する
    //
    // SNARK は任意の計算に適応できる
    // 秘密鍵などの特定の知識を開示せず、証明者と検証者のいずれとも対話せずに、
    // その知識の所有権を短時間かつ少ない計算量で証明できる非対話ゼロ知識証明の技術
    //
    // 繰り返し構造のある計算においては、STARKのほうが効率的
    // また、snark(js)のときのような、Trusted Setup(特定のサーキットに特化した証明キーと検証キーが生成)が
    // 必要ない
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    // ブロック生成報酬を受け取るアドレス
    let beneficiary = hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    // アドレス定義
    // 0x2c7536e3605d9c16a7a3d7b1898e529396a65c23
    // から
    // 0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0
    // に送金する
    let sender = hex!("2c7536e3605d9c16a7a3d7b1898e529396a65c23");
    let to = hex!("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");

    // ステートキーを作成している
    // Ethereumは各アカウントの状態をState Trieというデータ構造で管理しており、
    // このState Trieで特定のアカウントの情報にアクセスするため、
    // ステートキーを使用している
    let sender_state_key = keccak(sender);
    let to_state_key = keccak(to);
    
    // nibblesを生成
    // ニブルとは、半バイト（4ビット）のことで、1バイトのデータを2つのニブルに分割することができる。
    // 後のデータ構造やアルゴリズム内での扱いを効率よくするためにやる
    let sender_nibbles = Nibbles::from_bytes_be(sender_state_key.as_bytes()).unwrap();
    let to_nibbles = Nibbles::from_bytes_be(to_state_key.as_bytes()).unwrap();

    // アカウントを初期化
    // AccountRlpはEtuereumにおけるアカウントの状態を表すデータ構造
    // トランザクションの処理やアカウントの状態変更をシミュレートする際に利用する
    let sender_account_before = AccountRlp {
        nonce: 5.into(),
        balance: eth_to_wei(100_000.into()),
        storage_root: HashedPartialTrie::from(Node::Empty).hash(),
        code_hash: keccak([]),
    };
    // アカウント初期化受信側
    let to_account_before = AccountRlp::default();

    // EthereumではBitcoinのようなシンプルなMerkle Treeではなく、Merkle Patricia Trieという木構造が利用されている
    // https://docs.rs/eth_trie_utils/0.3.0/eth_trie_utils/partial_trie/enum.PartialTrie.html
    // キーと値のペアを効率的に管理し、検索することができる。また、Markle Treeと違い、部分更新が可能
    // ここでは最下層のデータを作成している。
    // nibblesがキーでvalueがデータ
    let state_trie_before = Node::Leaf {
        nibbles: sender_nibbles,
        // RLPエンコードとは、Recursive Length Prefixの略で、Ethereumでよく利用されている
        // >RLPは高度に最小化したシリアライゼーションフォーマットで、ネストされたByte配列を保存する目的のためにある。
        // >protobufやBSONなどとは違って、BooleanやFloat、DoubleやIntegerさえ定義しない
        // らしい
        value: rlp::encode(&sender_account_before).to_vec(),
    }
    .into();

    // 証明のためのデータ作成(送信側)
    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        transactions_trie: HashedPartialTrie::from(Node::Empty),
        receipts_trie: HashedPartialTrie::from(Node::Empty),
        storage_tries: vec![],
    };

    // senderからtoに送金した時のトランザクションデータをバイト列に変換したもの
    let txn = hex!("f861050a8255f094a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0648242421ba02c89eb757d9deeb1f5b3859a9d4d679951ef610ac47ad4608dc142beb1b7e313a05af7e9fbab825455d36c36c7f4cfcafbeafa9a77bdff936b52afb36d4fe4bcdd");
    let value = U256::from(100u32);

    // タイムスタンプ、ブロック番号などのブロック情報
    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(beneficiary),
        block_timestamp: 0x03e8.into(),
        block_number: 1.into(),
        block_difficulty: 0x020000.into(),
        block_random: H256::from_uint(&0x020000.into()),
        block_gaslimit: 0xff112233u32.into(),
        block_chain_id: 1.into(),
        block_base_fee: 0xa.into(),
        block_gas_used: 21032.into(),
        block_bloom: [0.into(); 8],
    };

    // コントラクトは今回は関係ない
    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);

    // Merkle Patricia Trieのデータを作成
    let expected_state_trie_after: HashedPartialTrie = {
        let txdata_gas = 2 * 16;
        let gas_used = 21_000 + txdata_gas;

        let sender_account_after = AccountRlp {
            balance: sender_account_before.balance - value - gas_used * 10,
            nonce: sender_account_before.nonce + 1,
            ..sender_account_before
        };
        let to_account_after = AccountRlp {
            balance: value,
            ..to_account_before
        };

        let mut children = core::array::from_fn(|_| Node::Empty.into());
        children[sender_nibbles.get_nibble(0) as usize] = Node::Leaf {
            nibbles: sender_nibbles.truncate_n_nibbles_front(1),
            value: rlp::encode(&sender_account_after).to_vec(),
        }
        .into();
        children[to_nibbles.get_nibble(0) as usize] = Node::Leaf {
            nibbles: to_nibbles.truncate_n_nibbles_front(1),
            value: rlp::encode(&to_account_after).to_vec(),
        }
        .into();
        Node::Branch {
            children,
            value: vec![],
        }
        .into()
    };

    // イーサリアムブロックチェーンに関連するデータ構造
    let receipt_0 = LegacyReceiptRlp {
        status: true,
        cum_gas_used: 21032.into(),
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    // トランザクションの実行結果
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie.insert(
        Nibbles::from_str("0x80").unwrap(),
        rlp::encode(&receipt_0).to_vec(),
    );
    // ブロック内のトランザクションを格納するトランザクショントライ
    let transactions_trie: HashedPartialTrie = Node::Leaf {
        nibbles: Nibbles::from_str("0x80").unwrap(),
        value: txn.to_vec(),
    }
    .into();

    // 証明のためのデータ作成(受信側)
    let trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };
    
    // 証明のためのデータ作成
    let inputs = GenerationInputs {
        signed_txn: Some(txn.to_vec()),
        withdrawals: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code,
        genesis_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 21032.into(),
        block_bloom_before: [0.into(); 8],
        block_bloom_after: [0.into(); 8],
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
        addresses: vec![],
    };

    // prove中のパフォーマンスを調査する
    let mut timing = TimingTree::new("prove", log::Level::Debug);
    // ZKのprove(証明)をここでやる。EVMが正しい挙動をしているという証明をしている
    let proof = prove::<F, C, D>(&all_stark, &config, inputs, &mut timing)?;
    // 100ms以上の処理時間がかかったもののみを出力
    timing.filter(Duration::from_millis(100)).print();

    // proof(証拠)のverify(検証)もやっておく
    verify_proof(&all_stark, proof, &config)
}

fn eth_to_wei(eth: U256) -> U256 {
    // 1 ether = 10^18 wei.
    eth * U256::from(10).pow(18.into())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}
