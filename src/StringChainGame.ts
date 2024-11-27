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
class WordChain extends Struct({
  currentWord: CircuitString,
  currentWordPrefix: CircuitString,
  currentWordLastChar: CircuitString,
  chainLength: Field,
  isValid: Bool,
}) {
  // Helper method to check if two words can be chained

  //    We can't use toString:

  //    1. Compiling WordChainVerifier...
  //    Error: x.toString() was called on a variable field element `x` in provable code.
  //    This is not supported, because variables represent an abstract computation,
  //    which only carries actual values during proving, but not during compiling.

  static canChainWords(
    word1: CircuitString,
    word1Prefix: CircuitString,
    word1LastChar: CircuitString,
    word2: CircuitString
  ): Bool {
    word1LastChar.length().assertEquals(1);

    word1Prefix.append(word1LastChar).hash().assertEquals(word1.hash());

    return CircuitString.toFields(word1LastChar)[0].equals(
      CircuitString.toFields(word2)[0]
    );
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
      privateInputs: [CircuitString, CircuitString, CircuitString],
      async method(
        state: Field,
        word: CircuitString,
        wordPrefix: CircuitString,
        wordLastChar: CircuitString
      ) {
        const chain = new WordChain({
          currentWord: word,
          currentWordPrefix: wordPrefix,
          currentWordLastChar: wordLastChar,
          chainLength: Field(1),
          isValid: Bool(true),
        });

        const stateHash = chain.toHash();

        state.assertEquals(stateHash);
      },
    },

    // Add a new word to the chain
    addWord: {
      privateInputs: [
        SelfProof,
        CircuitString,
        CircuitString,
        CircuitString,
        WordChain,
      ],
      async method(
        newState: Field,
        earlierProof: SelfProof<Field, void>,
        nextWord: CircuitString,
        nextWordPrefix: CircuitString,
        nextWordLastChar: CircuitString,
        previousChain: WordChain
      ) {
        earlierProof.verify();

        previousChain.toHash().assertEquals(earlierProof.publicInput);

        const canChain = WordChain.canChainWords(
          previousChain.currentWord,
          previousChain.currentWordPrefix,
          previousChain.currentWordLastChar,
          nextWord
        );

        const newChain = new WordChain({
          currentWord: nextWord,
          currentWordPrefix: nextWordPrefix,
          currentWordLastChar: nextWordLastChar,
          chainLength: previousChain.chainLength.add(1),
          isValid: Bool.and(previousChain.isValid, canChain),
        });

        const stateHash = newChain.toHash();

        newState.assertEquals(stateHash);
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
          chain1.currentWordPrefix,
          chain1.currentWordLastChar,
          chain2.currentWord
        );

        // Create merged chain
        const mergedChain = new WordChain({
          currentWord: chain2.currentWord,
          currentWordPrefix: chain2.currentWordPrefix,
          currentWordLastChar: chain2.currentWordLastChar,
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

  // Test word chain: cat -> tree -> elephant
  const word1 = CircuitString.fromString('cat');
  const word1Prefix = CircuitString.fromString('ca');
  const word1LastChar = CircuitString.fromString('t');
  const word2 = CircuitString.fromString('tree');
  const word2Prefix = CircuitString.fromString('tre');
  const word2LastChar = CircuitString.fromString('e');
  const word3 = CircuitString.fromString('elephant');
  const word3Prefix = CircuitString.fromString('elephan');
  const word3LastChar = CircuitString.fromString('t');

  console.log('\n2. Creating and verifying word chain...');

  // Initialize chain with first word
  const chain1 = new WordChain({
    currentWord: word1,
    currentWordPrefix: word1Prefix,
    currentWordLastChar: word1LastChar,
    chainLength: Field(1),
    isValid: Bool(true),
  });

  const state1 = chain1.toHash();

  const { proof: proof1 } = await WordChainVerifier.init(
    state1,
    word1,
    word1Prefix,
    word1LastChar
  );

  try {
    await verify(proof1.toJSON(), verificationKey);
    console.log('proof 1 verification succeeded');
  } catch (error) {
    console.error('proof 1 verification failed:', error);
  }

  const canChain12 = canChainWords(word1, word2);

  // Add second word
  const chain2 = new WordChain({
    currentWord: word2,
    currentWordPrefix: word2Prefix,
    currentWordLastChar: word2LastChar,
    chainLength: chain1.chainLength.add(1),
    isValid: Bool.and(chain1.isValid, Bool(canChain12)),
  });

  const state2 = chain2.toHash();

  const { proof: proof2 } = await WordChainVerifier.addWord(
    state2,
    proof1,
    word2,
    word2Prefix,
    word2LastChar,
    chain1
  );

  try {
    await verify(proof2.toJSON(), verificationKey);
    console.log('proof 2 verification succeeded');
  } catch (error) {
    console.error('earlierProof verification failed:', error);
  }

  const canChain23 = canChainWords(word2, word3);

  // Store the second chain state
  const chain3 = new WordChain({
    currentWord: word3,
    currentWordPrefix: word3Prefix,
    currentWordLastChar: word3LastChar,
    chainLength: chain2.chainLength.add(1),
    isValid: Bool.and(chain2.isValid, Bool(canChain23)),
  });

  const state3 = chain3.toHash();

  // Add third word
  const { proof: proof3 } = await WordChainVerifier.addWord(
    state3,
    proof2,
    word3,
    word3Prefix,
    word3LastChar,
    chain2
  );

  try {
    await verify(proof3.toJSON(), verificationKey);
    console.log('proof 3 verification succeeded');
  } catch (error) {
    console.error('earlierProof verification failed:', error);
  }

  // Create a second chain to demonstrate merging
  const word4 = CircuitString.fromString('trunt');
  const word4prefix = CircuitString.fromString('trun');
  const word4LastChar = CircuitString.fromString('t');
  const word5 = CircuitString.fromString('tking');
  const word5Prefix = CircuitString.fromString('tkin');
  const word5LastChar = CircuitString.fromString('g');

  const secondChain1 = new WordChain({
    currentWord: word4,
    currentWordPrefix: word4prefix,
    currentWordLastChar: word4LastChar,
    chainLength: Field(1),
    isValid: Bool(true),
  });

  const secondChain1Hash = secondChain1.toHash();

  const { proof: proof4 } = await WordChainVerifier.init(
    secondChain1Hash,
    word4,
    word4prefix,
    word4LastChar
  );

  try {
    await verify(proof4.toJSON(), verificationKey);
    console.log('second chain 1 verification succeeded');
  } catch (error) {
    console.error('second chain 1 verification failed:', error);
  }

  const canChain45 = canChainWords(word4, word5);

  const secondChain2 = new WordChain({
    currentWord: word5,
    currentWordPrefix: word5Prefix,
    currentWordLastChar: word5LastChar,
    chainLength: Field(2),
    isValid: Bool.and(secondChain1.isValid, Bool(canChain45)),
  });

  const secondChain2Hash = secondChain2.toHash();

  const { proof: proof5 } = await WordChainVerifier.addWord(
    secondChain2Hash,
    proof4,
    word5,
    word5Prefix,
    word5LastChar,
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
    currentWordPrefix: finalChain2.currentWordPrefix,
    currentWordLastChar: finalChain2.currentWordLastChar,
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
