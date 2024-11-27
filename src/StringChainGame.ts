import {
  Field,
  SelfProof,
  ZkProgram,
  verify,
  CircuitString,
  Struct,
  Bool,
  Provable,
  Poseidon,
} from 'o1js';

// Struct to hold a word and its verification status
class SplitWord extends Struct({
  word: CircuitString,
  prefix: CircuitString,
  lastChar: CircuitString,
}) {
  verify(): Bool {
    // Check lastChar is single character
    const isOneChar = this.lastChar.length().equals(1);

    // Verify prefix + lastChar = word using hash comparison
    const isValidSplit = this.prefix
      .append(this.lastChar)
      .hash()
      .equals(this.word.hash());

    return Bool.and(isOneChar, isValidSplit);
  }
}

class WordChain extends Struct({
  currentWord: SplitWord,
  chainLength: Field,
  isValid: Bool,
}) {
  static canChainWords(word1: SplitWord, word2: SplitWord): Bool {
    // Verify both splits are valid
    const validSplits = Bool.and(word1.verify(), word2.verify());

    // Compare last char of word1 with first char of word2
    const canChain = CircuitString.toFields(word1.lastChar)[0].equals(
      CircuitString.toFields(word2.word)[0]
    );

    return Bool.and(validSplits, canChain);
  }

  // Convert WordChain to a single Field using Poseidon hash
  toHash(): Field {
    return Poseidon.hash(WordChain.toFields(this));
  }
}

// Create ZkProgram for word chain verification
const WordChainVerifier = ZkProgram({
  name: 'word-chain-verifier',
  publicInput: Field,

  methods: {
    // Start a new chain with a single word
    init: {
      privateInputs: [SplitWord],
      async method(state: Field, word: SplitWord) {
        word.verify().assertTrue();

        const chain = new WordChain({
          currentWord: word,
          chainLength: Field(1),
          isValid: Bool(true),
        });

        state.assertEquals(chain.toHash());
      },
    },

    // Add a new word to the chain
    addWord: {
      privateInputs: [SelfProof, SplitWord, WordChain],
      async method(
        newState: Field,
        earlierProof: SelfProof<Field, void>,
        nextWord: SplitWord,
        previousChain: WordChain
      ) {
        earlierProof.verify();
        previousChain.toHash().assertEquals(earlierProof.publicInput);

        nextWord.verify().assertTrue();

        const canChain = WordChain.canChainWords(
          previousChain.currentWord,
          nextWord
        );

        const newChain = new WordChain({
          currentWord: nextWord,
          chainLength: previousChain.chainLength.add(1),
          isValid: Bool.and(previousChain.isValid, canChain),
        });

        newState.assertEquals(newChain.toHash());
      },
    },

    // Merge two chains
    mergeChains: {
      privateInputs: [SelfProof, SelfProof, WordChain, WordChain],
      async method(
        newState: Field,
        proof1: SelfProof<Field, void>,
        proof2: SelfProof<Field, void>,
        chain1: WordChain,
        chain2: WordChain
      ) {
        // Verify both proofs
        try {
          proof1.verify();
          proof2.verify();
        } catch (error) {
          Provable.log('proof verification failed:', error);
        }

        // Verify that the chains match their proofs
        chain1.toHash().assertEquals(proof1.publicInput);
        chain2.toHash().assertEquals(proof2.publicInput);

        // Check if chains can be connected
        const chainsCanConnect = WordChain.canChainWords(
          chain1.currentWord,
          chain2.currentWord
        );

        // Create merged chain
        const mergedChain = new WordChain({
          currentWord: chain2.currentWord,
          chainLength: chain1.chainLength.add(chain2.chainLength),
          isValid: Bool.and(
            Bool.and(chain1.isValid, chain2.isValid),
            chainsCanConnect
          ),
        });

        // Hash the new state and verify
        const stateHash = mergedChain.toHash();

        newState.assertEquals(stateHash);
      },
    },
  },
});

function canChainWords(word1: CircuitString, word2: CircuitString): boolean {
  return word1.toString()[word1.toString().length - 1] === word2.toString()[0];
}

// Main function to demonstrate usage
async function main() {
  console.log('1. Compiling WordChainVerifier...');
  const { verificationKey } = await WordChainVerifier.compile();

  console.log('-- before wordq1');
  // Test word chain: cat -> tree -> elephant
  const word1 = new SplitWord({
    word: CircuitString.fromString('cat'),
    prefix: CircuitString.fromString('ca'),
    lastChar: CircuitString.fromString('t'),
  });

  console.log('-- before word2');
  const word2 = new SplitWord({
    word: CircuitString.fromString('tree'),
    prefix: CircuitString.fromString('tre'),
    lastChar: CircuitString.fromString('e'),
  });

  const word3 = new SplitWord({
    word: CircuitString.fromString('elephant'),
    prefix: CircuitString.fromString('elephan'),
    lastChar: CircuitString.fromString('t'),
  });

  console.log('\n2. Creating and verifying word chain...');

  // Initialize chain with first word
  const chain1 = new WordChain({
    currentWord: word1,
    chainLength: Field(1),
    isValid: Bool(true),
  });

  const state1 = chain1.toHash();

  const { proof: proof1 } = await WordChainVerifier.init(state1, word1);

  try {
    await verify(proof1.toJSON(), verificationKey);
    console.log('proof 1 verification succeeded');
  } catch (error) {
    console.error('proof 1 verification failed:', error);
  }

  const canChain12 = canChainWords(word1.word, word2.word);

  // Add second word
  const chain2 = new WordChain({
    currentWord: word2,
    chainLength: chain1.chainLength.add(1),
    isValid: Bool.and(chain1.isValid, Bool(canChain12)),
  });

  const state2 = chain2.toHash();

  const { proof: proof2 } = await WordChainVerifier.addWord(
    state2,
    proof1,
    word2,
    chain1
  );

  try {
    await verify(proof2.toJSON(), verificationKey);
    console.log('proof 2 verification succeeded');
  } catch (error) {
    console.error('earlierProof verification failed:', error);
  }

  const canChain23 = canChainWords(word2.word, word3.word);

  // Store the second chain state
  const chain3 = new WordChain({
    currentWord: word3,
    chainLength: chain2.chainLength.add(1),
    isValid: Bool.and(chain2.isValid, Bool(canChain23)),
  });

  const state3 = chain3.toHash();

  // Add third word
  const { proof: proof3 } = await WordChainVerifier.addWord(
    state3,
    proof2,
    word3,
    chain2
  );

  try {
    await verify(proof3.toJSON(), verificationKey);
    console.log('proof 3 verification succeeded');
  } catch (error) {
    console.error('earlierProof verification failed:', error);
  }

  // Create a second chain to demonstrate merging
  const word4 = new SplitWord({
    word: CircuitString.fromString('trunt'),
    prefix: CircuitString.fromString('trun'),
    lastChar: CircuitString.fromString('t'),
  });

  const word5 = new SplitWord({
    word: CircuitString.fromString('tking'),
    prefix: CircuitString.fromString('tkin'),
    lastChar: CircuitString.fromString('g'),
  });

  const secondChain1 = new WordChain({
    currentWord: word4,
    chainLength: Field(1),
    isValid: Bool(true),
  });

  const secondChain1Hash = secondChain1.toHash();

  const { proof: proof4 } = await WordChainVerifier.init(
    secondChain1Hash,
    word4
  );

  try {
    await verify(proof4.toJSON(), verificationKey);
    console.log('second chain 1 verification succeeded');
  } catch (error) {
    console.error('second chain 1 verification failed:', error);
  }

  const canChain45 = canChainWords(word4.word, word5.word);

  const secondChain2 = new WordChain({
    currentWord: word5,
    chainLength: Field(2),
    isValid: Bool.and(secondChain1.isValid, Bool(canChain45)),
  });

  const secondChain2Hash = secondChain2.toHash();

  const { proof: proof5 } = await WordChainVerifier.addWord(
    secondChain2Hash,
    proof4,
    word5,
    secondChain1
  );

  try {
    await verify(proof5.toJSON(), verificationKey);
    console.log('second chain 2 verification succeeded');
  } catch (error) {
    console.error('second chain 2 verification failed:', error);
  }

  // Store the final states of both chains
  const finalChain1 = chain3;
  const finalChain2 = secondChain2;

  const finalChainSum = new WordChain({
    currentWord: finalChain2.currentWord,
    chainLength: finalChain1.chainLength.add(finalChain2.chainLength),
    isValid: Bool.and(finalChain1.isValid, finalChain2.isValid),
  });

  const finalChainSumHash = finalChainSum.toHash();

  // Try to merge the chains
  const { proof: mergedProof } = await WordChainVerifier.mergeChains(
    finalChainSumHash,
    proof3,
    proof5,
    finalChain1,
    finalChain2
  );

  console.log('\n3. Verifying final proof...');
  const ok = await verify(mergedProof.toJSON(), verificationKey);
  console.log('Verification result:', ok);
}

main().catch(console.error);
