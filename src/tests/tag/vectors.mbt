// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Two files the reference implementation wrote, and the plaintext they carry,
/// so that "a file age seals, this library opens" is a test rather than a claim.
///
/// Both were sealed by age v1.3.2, to the identity its own test plugin holds:
/// the one that plugin derives from the string `age-plugin-tagtest`.
/// The recipients below are that identity's public halves, and the plaintext is
/// the sentence the rest of this library's tests use.
///
/// Nothing here is this library's work. The tag and the encapsulation inside a
/// stanza are drawn from the air by the sender, so a second run of age would
/// write different files and prove the same thing: what is pinned is that this
/// library reads what age wrote.

///|
/// The plaintext both files carry.
pub let plain : Bytes = b"the quick brown fox jumps over the lazy dog\n"

///|
/// Its SHA-256, as hex, which is what the tests compare against.
pub let digest : String = "1153a4080f1fcb04425aa0b841c2b14606fe6df25d9076d2a1face2d5af57129"

///|
/// A file sealed to the `p256tag` recipient of that identity.
pub let classic : String = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHAyNTZ0YWcgVTM5" +
  "ZTRBIEJHRzUwTXY0Z1BVcDl2NWJ2WEh2ZXExTVR1bHdsWGU1" +
  "Tm9MRWt2VVg0NnNNMXNyYU5PRkwvMzJkbG9Udit4VVh0aWV6" +
  "Q0RzTzZYZm16Yk5aOUVVQ0lUdwpmMHRBOEx6dHBxTGFET0tP" +
  "Y1lCN2RKci9MWXVleG1VV1BxWXNqU1p4RGdFCi0tLSA5MThR" +
  "MHdOcG5JRGJVcXR0cFptUHluOHBremtacSs5a29ycFNkUC96" +
  "NVJNCkShgUo0m1r+Kwq1yiLf4ezkMelth+N0V+ExzJ1DnXGt" +
  "VWdXlkj7VIfpgx5hw5EfgFPJlenxwyCsLiS1Z+Kl0o0C5QzQ" +
  "cQI2HC6+t3g="

///|
/// A file sealed to the `mlkem768p256tag` recipient of the same
/// identity.
pub let hybrid : String = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IG1sa2VtNzY4cDI1" +
  "NnRhZyBvaDc1OUEgVXNIM05iZ2pKNEtBaEhMNlg2V0g2cWpG" +
  "VFJkbGtPT1VtSkpYd3BrVk1NWnFGd0hLSHN4TDhGQ0EzQ2x1" +
  "cGhNaVJaQkcwQzR1NzFickVhdUJFTW9HOE9ZM2drTGdCeVZi" +
  "Y3RpNnpjVVQ4Z1IvWUhtM1IwdXljem1sRUhYcEZzcllpQUY4" +
  "UmxTeFJhNmpJN2hDRW1qM21xWG95SlRERzZvbTVaOENiREg1" +
  "QTE4ZVRHLzBiODA3MzdYd05oUE1XZ25icTVFQjd1MlJINWVI" +
  "c3dYUWpLOFRQRnFPdmduMnpnaVFVNTVwZ0I3S0xDNTNyNEwv" +
  "NUNRbkh6aHozMVRTODdRRWJ6eEs5akJrTGN0M3YyT1VOOXNZ" +
  "OW9kVHErbW1DaFpPUWgrV1NVdGxjalJUN296TGExYS9TejFk" +
  "SWh5NVlSVzNPYnhzNkVJTkpOZmpTQ1FVMDAvZHd1dmUxci95" +
  "R3AvNy9JeFlFUTV3ZVliZTROZm83MXVYUEZXVnBSOUFJVVA2" +
  "dlpIbFgxRXVsRjlPRXdpdXRxZ0w5T2hZRms0bTdQZzY3ejlR" +
  "STA1ZjIzYVJjd1pqcEFyN3podnRNcis3RFRLY3FhM0lxQkpL" +
  "UGllcjEzUGtlYitPZlBuQ0lQZSswd1BqRitMemRRV2xQSkhY" +
  "ZzZBRlpoQlh1MGZKYUlRcnM2R0NzaW4yemZLaXZUWnFJeDQr" +
  "M0hDZ3lkR2R3TjhKWS9aaUJFK2hDVjFXd3ZJTkM2bjRzRzR2" +
  "M0FVWXBiVHZ0aVQ0YjltcGtWQTlGaDh3YndYMnduR1NiN2pS" +
  "R2xXYnM4VVNFWkR2Rks3bVdNODBSV3l1WjFHV1B0T2xkODd3" +
  "SzljSVFwSEwvdmZwdzBMRjQ5aE1BaXhTS09LMm1WQ0NUSVNQ" +
  "TnVtWDlSV0Y0QUZuc1NzR01HZkhUWXZNVDZRRklzU0loN2Fm" +
  "Z0JmcWx0TGFIekZ3K0lUZE4wd2c4NjZGcEVUK2JJQWRpNkJ4" +
  "c3dPM2NRWWU1ZGtYOGw5TmNZYXQ5aTBvNHVjNkVSV25PN1dK" +
  "cnJ3QjE5VS8xd0FyNEVoUFBJN2wvOWZnUFcwSURCdjRHT080" +
  "TWtNMjJaa3hScTRhckczUlQ5UzAvaDhQYzQzZHpER3Y1dnFu" +
  "M28waGo3MFI3Snh0ZHpHZGN5d1NWeTBvUGdWWHpBbWxRUjRi" +
  "eTY0bWNGemVueGttTzlFWEdPNlhlOTNmRWJkY3M2ZFFUbkdp" +
  "RDJKNmc0cEZCcElDcVhFaUowSFpnWU9wZ2wvVldPdXdXcXRO" +
  "L0t6emtPN0JRUC91R1lCMCtEM0VyMlR4L1NneHVPcGFkV1JX" +
  "NUI1MW9VZlVqbUxnUWlhOTZQQlpEQVIrWURVVVc1NnNHajRH" +
  "TVN5a1hDMjBVcjJjVW5qYWFZeEJzWHRzbHVPY01ZTnFoeEtL" +
  "MU9FOW11K2pSWnNseDcyS0JPUWtBR01XbURtM0pmeU5tYlBr" +
  "S2VhaEpWV3RndHpGblhPblljRTV0Uzh1Qk9ueUZYZGwrNm1k" +
  "NEp5NzJ6QlJYdEh6VVUxNjhYSjg5NG4wV0JLRlliQ3gxb3VP" +
  "d1BhRE1LNXRCK1ZRQlllSkRpMHVDYUxYVW40S0ljbk9aWnd0" +
  "S21tZEVPbkpqUm80R1J2cXRjWnI0cEV6aVJoVmlUd2NwK1V3" +
  "bmk3RHltUit1aWFWb1MzU3UvTFlYVGR1SW01OGxkY0FZczZN" +
  "aE4wVkJQRXRJZ0JwcW1qVkFqVHhsVzZTUlNUZkhPQmEvU0lG" +
  "V1BkcitVbWdEU3hwVzg5WCtSTkFWcGRwN09SN2htUjNVeVlu" +
  "b2dpajVTV1VJbjFuclVXd3p4ZGt2elB2SzFOdlh2ZC8xUTk0" +
  "dXEvUVpLNEs4RUgvL3pOTmhnZDdLdVlTdDRRMjVxKzR4ZW9z" +
  "d05EcGp5V0xlYU9ETzh4cmtxK0RuRzhFdElQamRXSWYyYkxB" +
  "NmptRGlGUytCM2pMNndVTFlmd2lmeGxud1hKanRMdzlkUGhy" +
  "bE9KUVNsaUt3d0Vpa0JpaTZVemhsMzNQWVJNejQ5SGZoS3Rp" +
  "ZWcKQnlpOHNvL1BQZndPLzEwMklUaVZDSWVmbEswQUZtSWps" +
  "RzFSdVhxcGE4ZwotLS0gT0NFT1ZyL2dCSVowQ1RKdFJnWDFU" +
  "MnhXclBkdXZLbmg2MGdPM1NoT3RNawp5Yt2Q3WVkLGuKVxKj" +
  "/gIcYFP1uc3LSopLiHfpUI3ulSsLnmOSoqvE0yMEY9bsfP8L" +
  "jVs/VbHTG8zxccTSoZLdVJAevNMkRDzewU0p"
