/**
 * Paylaşılacak raporlar için IP maskeleme. IP adresi KVKK'ya göre kişisel veridir; rapor
 * SOC dışına (yöneticiye, hocaya) gidecekse adresin yalnızca ilk kısmı kalır: 93.x.x.x
 */

const IPV4 = /\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g
// En az iki ':' içeren onaltılık gruplar (IPv6); saat (21:06:21) yalnızca rakam ve 2 grup olduğu
// için ayrıca kontrol edilir
const IPV6 = /\b([0-9a-f]{1,4})(?::[0-9a-f]{0,4}){2,7}\b/gi

function maskV6(match: string, first: string): string {
  const isTime = /^\d{1,2}:\d{2}(:\d{2})?$/.test(match)
  return isTime ? match : `${first}:x:x::x`
}

export function maskIps(text: string): string {
  return text.replace(IPV4, (_m, first: string) => `${first}.x.x.x`).replace(IPV6, maskV6)
}

/** Nesnenin içindeki tüm metinleri maskeler (anahtarlar değil, değerler). */
export function maskDeep<T>(value: T): T {
  if (typeof value === 'string') return maskIps(value) as T
  if (Array.isArray(value)) return value.map(maskDeep) as T
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, maskDeep(v)]),
    ) as T
  }
  return value
}
