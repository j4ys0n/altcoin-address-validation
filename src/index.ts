import { base58_to_binary } from 'base58-js'
import { bech32, bech32m } from 'bech32'
import { createHash } from 'sha256-uint8array'

const sha256 = (payload: Uint8Array) => createHash().update(payload).digest()

enum Network {
  mainnet = 'mainnet',
  testnet = 'testnet',
  regtest = 'regtest'
}

enum AddressType {
  p2pkh = 'p2pkh',
  p2sh = 'p2sh',
  p2wpkh = 'p2wpkh',
  p2wsh = 'p2wsh',
  p2tr = 'p2tr'
}

type AddressInfo = {
  bech32: boolean
  network: Network
  address: string
  type: AddressType
  chains: string[]
}

type NetworkAddress = {
  type: AddressType
  network: Network
  chains: string[]
}

type NetworkAddresses = {
  [key: number]: NetworkAddress
}

const mapPrefixToNetwork: { [key: string]: { chain: string; network: Network } } = {
  bc: {
    chain: 'bitcoin',
    network: Network.mainnet
  },
  tb: {
    chain: 'bitcoin',
    network: Network.testnet
  },
  bcrt: {
    chain: 'bitcoin',
    network: Network.regtest
  },
  ltc: {
    chain: 'litecoin',
    network: Network.mainnet
  },
  tltc: {
    chain: 'litecoin',
    network: Network.testnet
  },
  vg: {
    chain: 'verge',
    network: Network.mainnet
  },
  btg: {
    chain: 'bitcoin gold',
    network: Network.mainnet
  }
}

const addressTypes: NetworkAddresses = {
  // bitcoin
  0x00: {
    type: AddressType.p2pkh,
    network: Network.mainnet,
    chains: ['bitcoin']
  },
  0x05: {
    type: AddressType.p2sh,
    network: Network.mainnet,
    chains: ['bitcoin', 'litecoin']
  },
  0x6f: {
    type: AddressType.p2pkh,
    network: Network.testnet,
    chains: ['bitcoin', 'litecoin']
  },
  0xc4: {
    type: AddressType.p2sh,
    network: Network.testnet,
    chains: ['bitcoin', 'dogecoin', 'litecoin']
  },
  // litecoin
  0x30: {
    type: AddressType.p2pkh,
    network: Network.mainnet,
    chains: ['litecoin']
  },
  0x32: {
    type: AddressType.p2sh,
    network: Network.mainnet,
    chains: ['litecoin']
  },
  // dogecoin
  0x1e: {
    type: AddressType.p2pkh,
    network: Network.mainnet,
    chains: ['dogecoin', 'verge', 'bitcoin gold']
  },
  0x16: {
    type: AddressType.p2sh,
    network: Network.mainnet,
    chains: ['dogecoin']
  },
  // verge
  0x21: {
    type: AddressType.p2sh,
    network: Network.mainnet,
    chains: ['verge']
  },
  // dash
  0x4c: {
    type: AddressType.p2pkh,
    network: Network.mainnet,
    chains: ['dash']
  },
  0x10: {
    type: AddressType.p2sh,
    network: Network.mainnet,
    chains: ['dash']
  },
  // bitcoin gold
  0x17: {
    type: AddressType.p2sh,
    network: Network.mainnet,
    chains: ['bitcoin gold']
  }
}

const parseBech32 = (address: string): AddressInfo => {
  let decoded

  try {
    if (address.startsWith('bc1p') || address.startsWith('tb1p') || address.startsWith('bcrt1p')) {
      decoded = bech32m.decode(address)
    } else {
      decoded = bech32.decode(address)
    }
  } catch (error) {
    throw new Error('Invalid address')
  }

  const hrp = mapPrefixToNetwork[decoded.prefix]

  const network: Network | undefined = hrp != null ? hrp.network : undefined

  if (network === undefined) {
    throw new Error('Invalid address')
  }

  const witnessVersion = decoded.words[0]

  if (witnessVersion < 0 || witnessVersion > 16) {
    throw new Error('Invalid address')
  }
  const data = bech32.fromWords(decoded.words.slice(1))

  let type

  if (data.length === 20) {
    type = AddressType.p2wpkh
  } else if (witnessVersion === 1) {
    type = AddressType.p2tr
  } else {
    type = AddressType.p2wsh
  }

  return {
    bech32: true,
    network,
    address,
    type,
    chains: [hrp.chain]
  }
}

const getAddressInfo = (address: string): AddressInfo => {
  let decoded: Uint8Array
  const prefix = address.substr(0, 2).toLowerCase()

  if (prefix === 'bc' || prefix === 'tb') {
    return parseBech32(address)
  }

  try {
    decoded = base58_to_binary(address)
  } catch (error) {
    throw new Error('Invalid address')
  }

  const { length } = decoded

  if (length !== 25) {
    throw new Error('Invalid address')
  }

  const version = decoded[0]

  const checksum = decoded.slice(length - 4, length)
  const body = decoded.slice(0, length - 4)

  const expectedChecksum = sha256(sha256(body)).slice(0, 4)

  if (checksum.some((value: number, index: number) => value !== expectedChecksum[index])) {
    throw new Error('Invalid address')
  }

  const validVersions = Object.keys(addressTypes).map(Number)

  if (!validVersions.includes(version)) {
    throw new Error('Invalid address')
  }

  

  const addressType = addressTypes[version]

  return {
    ...addressType,
    address,
    bech32: false
  }
}

const validate = (address: string, network?: Network) => {
  try {
    const addressInfo = getAddressInfo(address)

    if (network) {
      return network === addressInfo.network
    }

    return true
  } catch (error) {
    return false
  }
}

export { getAddressInfo, Network, AddressType, AddressInfo, validate }
export default validate
