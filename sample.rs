#[test]
fn test_simple_transfer() -> anyhow::Result<()> {
    init_logger();

    // 初期設定
    // stark関連のスタンダードな設定をここで行う。
    // snarkと違い、starkは大量のデータや複雑な計算に対しても効率的に動作する
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

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
    let sender_nibbles = Nibbles::from(sender_state_key);
    let to_nibbles = Nibbles::from(to_state_key);
    // 送金額
    let value = U256::from(100u32);

    // アカウントを初期化
    // AccountRlpはEtuereumにおけるアカウントの状態を表すデータ構造
    // トランザクションの処理やアカウントの状態変更をシミュレートする際に利用する
    let sender_account_before = AccountRlp {
        nonce: 5.into(),
        balance: eth_to_wei(100_000.into()),
        storage_root: PartialTrie::Empty.calc_hash(),
        // code_hashが空ってことはEOAを表している？
        code_hash: keccak([]),
    };

    // EthereumではBitcoinのようなシンプルなMerkle Treeではなく、Merkle Patricia Trieという木構造が利用されている
    // https://docs.rs/eth_trie_utils/0.3.0/eth_trie_utils/partial_trie/enum.PartialTrie.html
    // キーと値のペアを効率的に管理し、検索することができる。また、Markle Treeと違い、部分更新が可能
    // ここでは最下層のデータを作成している。
    // nibblesがキーでvalueがデータ
    let state_trie_before = PartialTrie::Leaf {
        nibbles: sender_nibbles,
        // RLPエンコードとは、Recursive Length Prefixの略で、Ethereumでよく利用されている
        // >RLPは高度に最小化したシリアライゼーションフォーマットで、ネストされたByte配列を保存する目的のためにある。
        // >protobufやBSONなどとは違って、BooleanやFloat、DoubleやIntegerさえ定義しない
        // らしい
        value: rlp::encode(&sender_account_before).to_vec(),
    };
    // 証明のためのデータ作成
    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        transactions_trie: PartialTrie::Empty,
        receipts_trie: PartialTrie::Empty,
        storage_tries: vec![],
    };

    // senderからtoにvalue送金した時のトランザクションデータをバイト列に変換したもの
    let txn = hex!("f861050a8255f094a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0648242421ba02c89eb757d9deeb1f5b3859a9d4d679951ef610ac47ad4608dc142beb1b7e313a05af7e9fbab825455d36c36c7f4cfcafbeafa9a77bdff936b52afb36d4fe4bcdd");

    // タイムスタンプ、ブロック番号などのブロック情報
    let block_metadata = BlockMetadata::default();
    // 証明のためのデータ作成
    let inputs = GenerationInputs {
        signed_txns: vec![txn.to_vec()],
        tries: tries_before,
        contract_code: HashMap::new(),
        block_metadata,
    };
    // prove中のパフォーマンスを調査する
    let mut timing = TimingTree::new("prove", log::Level::Debug);

    // ZKのprove(証明)をここでやる。EVMが正しい挙動をしているという証明をしている
    let proof = prove::<F, C, D>(&all_stark, &config, inputs, &mut timing)?;
    // 100ms以上の処理時間がかかったもののみを出力
    timing.filter(Duration::from_millis(100)).print();

    // txの後で期待する動作を定義
    let expected_state_trie_after = {
        // 送金したので、残高が減っている
        let sender_account_after = AccountRlp {
            balance: sender_account_before.balance - value, // TODO: Also subtract gas_used * price. まだガスプライスの計算は行なっていない？
            ..sender_account_before
        };
        let to_account_after = AccountRlp {
            balance: value,
            ..AccountRlp::default()
        };

        let mut children = std::array::from_fn(|_| PartialTrie::Empty.into());
        children[sender_nibbles.get_nibble(0) as usize] = PartialTrie::Leaf {
            nibbles: sender_nibbles.truncate_n_nibbles_front(1),
            value: rlp::encode(&sender_account_after).to_vec(),
        }
        .into();
        children[to_nibbles.get_nibble(0) as usize] = PartialTrie::Leaf {
            nibbles: to_nibbles.truncate_n_nibbles_front(1),
            value: rlp::encode(&to_account_after).to_vec(),
        }
        .into();
        PartialTrie::Branch {
            children,
            value: vec![],
        }
    };

    // ZK Proofのstate rootと素で計算した送金後のステートルートを比較する
    assert_eq!(
        proof.public_values.trie_roots_after.state_root,
        expected_state_trie_after.calc_hash()
    );

    // proof(証拠)のverify(検証)もやっておく
    verify_proof(all_stark, proof, &config)
}
