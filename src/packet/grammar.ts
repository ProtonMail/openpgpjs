import { type Config } from '../config';
import enums from '../enums';
import util from '../util';

export class GrammarError extends Error {
  constructor(...params: any[]) {
    super(...params);

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, GrammarError);
    }

    this.name = 'GrammarError';
  }
}


const isValidLiteralMessage = (tagList: enums.packet[], _acceptPartial: boolean) => tagList.length === 1 && tagList[0] === enums.packet.literalData;
const isValidCompressedMessage = (tagList: enums.packet[], _acceptPartial: boolean) => tagList.length === 1 && tagList[0] === enums.packet.compressedData;
const isValidEncryptedMessage = (tagList: enums.packet[], acceptPartial: boolean) => {
  // Encrypted Message: Encrypted Data | ESK Sequence, Encrypted Data.
  const isValidESKSequence = (tagList: enums.packet[], _acceptPartial: boolean) => (
    tagList.every(packetTag => new Set([enums.packet.publicKeyEncryptedSessionKey, enums.packet.symEncryptedSessionKey]).has(packetTag))
  );
  const encryptedDataPacketIndex = tagList.findIndex(tag => new Set([enums.packet.aeadEncryptedData, enums.packet.symmetricallyEncryptedData, enums.packet.symEncryptedIntegrityProtectedData]).has(tag));
  if (encryptedDataPacketIndex < 0) {
    return isValidESKSequence(tagList, acceptPartial);
  }

  return (encryptedDataPacketIndex === tagList.length - 1) &&
    isValidESKSequence(tagList.slice(0, encryptedDataPacketIndex), acceptPartial);
};

const isValidSignedMessage = (tagList: enums.packet[], acceptPartial: boolean) => {
  // Signature Packet, OpenPGP Message | One-Pass Signed Message.
  if (tagList.findIndex(tag => tag === enums.packet.signature) === 0) {
    return isValidOpenPGPMessage(tagList.slice(1), acceptPartial);
  }

  // One-Pass Signed Message:
  //    One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
  if (tagList.findIndex(tag => tag === enums.packet.onePassSignature) === 0) {
    const correspondingSigPacketIndex = util.findLastIndex(tagList, tag => tag === enums.packet.signature);
    if (correspondingSigPacketIndex !== tagList.length - 1 && !acceptPartial) {
      return false;
    }
    return isValidOpenPGPMessage(tagList.slice(1, correspondingSigPacketIndex < 0 ? undefined : correspondingSigPacketIndex), acceptPartial);
  }

  return false;
};

const isUnknownPacketTag = (tag: number): tag is enums.packet => {
  try {
    enums.read(enums.packet, tag);
    return false;
  } catch (e) {
    return true;
  }
};

/**
 * Implements grammar checks based on https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3 .
 * @param notNormalizedList - list of packet tags to validate
 * @param acceptPartial - whether the list of tags corresponds to a partially-parsed message
 * @returns whether the list of tags is valid
 */
const isValidOpenPGPMessage = (
  notNormalizedList: number[] /** might have unknown tags */,
  acceptPartial: boolean
): boolean => {
  // Take care of packet tags that can appear anywhere in the sequence:
  // 1. A Marker packet (Section 5.8) can appear anywhere in the sequence.
  // 2. An implementation MUST be able to process Padding packets anywhere else in an OpenPGP stream so that future revisions of this document may specify further locations for padding.
  // 3. An unknown non-critical packet MUST be ignored (criticality its enforced on parsing).
  const normalizedList: enums.packet[] = notNormalizedList.filter(tag => (
    tag !== enums.packet.marker &&
    tag !== enums.packet.padding &&
      !isUnknownPacketTag(tag)
  ));

  return isValidLiteralMessage(normalizedList, acceptPartial) ||
    isValidCompressedMessage(normalizedList, acceptPartial) ||
    isValidEncryptedMessage(normalizedList, acceptPartial) ||
    isValidSignedMessage(normalizedList, acceptPartial);
};


/**
 * Grammar validation cannot be run before message integrity has been enstablished,
 * to avoid leaking info about the unauthenticated message structure.
 * This validator allows checking the grammar validity in an async manner, by storing the validity
 * status during parsing but only reporting it after authentication has been completed.
 * `markAuthenticated` needs to be invoked to notify the validator of successful authentication.
 */
export const getAsyncMessageGrammarValidator = () => {
  const getPromiseWithResolvers = <T>() => {
    let resolve: (value?: any) => void;
    let reject: (reason?: any) => void;
    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    promise.catch(() => {}); // avoid uncaught promise errors
    // @ts-ignore false positive for used-before-assigned
    return { promise, reject, resolve };
  };

  const grammarCheckPromiseWithResolvers = getPromiseWithResolvers<true>();
  let authenticated = false;
  let logged = false;

  return {
    /**
     * Notify the validator that authentication for the data being validated has been confirmed.
     *
     * If the validation result is already available, it is also returned.
     * The result will not be available if the the data has only been partially parsed, and
     * no grammar errors have been encountered in the partial data.
     * In such a case, the result will be later returned by subsequent calls to
     * `messageGrammarValidatorWithLatentReporting`.
     * @returns `Promise<true>` on successful grammar validation, a rejected promise if unsuccesssful,
     *    or `Promise<undefined>` if still pending.
     */
    markAuthenticated: async () => {
      authenticated = true;
      if (await util.isPromisePending(grammarCheckPromiseWithResolvers.promise) === false) {
        return grammarCheckPromiseWithResolvers.promise;
      }
    },
    /**
     * Run grammar check over `list`.
     * The result (when available) is stored in an internal promise that is only returned after `markAuthenticated`
     * has been called.
     * @returns `Promise<true>` on successful grammar validation, a rejected promise if unsuccesssful,
     *    or `Promise<undefined>` if still pending (either because of partial parsing or waiting for authentication
     * to be confirmed.
     */
    messageGrammarValidatorWithLatentReporting: async (list: number[], isPartial: boolean, config: Config) => {
      const isValid = isValidOpenPGPMessage(list, isPartial);
      if (isValid) {
        if (!isPartial) {
          grammarCheckPromiseWithResolvers.resolve(true); // noop if already rejected
        }
      } else {
        const error = new GrammarError(`Data does not respect OpenPGP grammar [${list}]`);
        if (!logged) {
          config.pluggableGrammarErrorReporter?.(error.message);
          util.printDebugError(error);
          logged = true;
        }
        if (config.enforceGrammar) {
          grammarCheckPromiseWithResolvers.reject(error); // reject as early as possible
        } else {
          // eslint-disable-next-line no-lonely-if
          if (!isPartial) {
            grammarCheckPromiseWithResolvers.resolve(true); // noop if already rejected
          }
        }
      }

      if (authenticated && await util.isPromisePending(grammarCheckPromiseWithResolvers.promise) === false) {
        return grammarCheckPromiseWithResolvers.promise;
      }
    }
  };
};

/**
 * This grammar validator throws as soon as an invalid packet sequence is detected during parsing.
 * It MUST NOT be used when parsing unauthenticated decrypted data, to avoid instantiating decryption oracles:
 * use `getAsyncMessageGrammarValidator()` instead
 */
export const getSyncMessageGrammarValidator = () => {
  let logged = false;

  return (list: number[], acceptPartial: boolean, config: Config) => {
    if (isValidOpenPGPMessage(list, acceptPartial)) {
      return;
    }

    const error = new GrammarError(`Data does not respect OpenPGP grammar [${list}]`);
    if (config.enforceGrammar) {
      config.pluggableGrammarErrorReporter?.(error.message);
      throw error;
    } else if (!logged) {
      config.pluggableGrammarErrorReporter?.(error.message);
      util.printDebugError(error);
      logged = true;
    }
  };
};

