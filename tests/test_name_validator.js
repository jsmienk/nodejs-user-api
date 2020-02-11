function isValidName(name) {
    // Test for invalid characters
    return /^([\p{L}][',.-]?[ ]?)+$/u.test(name.trim())
}

const cases = [
    // Valid names
    [ "Jeroen Smienk", true ],
    [ "Serçan Celik", true ],
    [ "André Smienk", true ],
    [ "Angela Smienk-Kaalverink", true ],
    [ "Hector Sausage-Hausen", true ],
    [ "Martin Luther King, Jr.", true ],
    [ "Mathias d'Arras", true ],
    [ "日本人 の氏名", true ],
    [ "O'Harris", true ],
    // Invalid names
    [ ".Jeroen Smienk", false ],
    [ "J,-eroen Smienk", false ],
    [ "J-", false ],
    [ "Jeroen  Smienk", false ],
    [ "", false ],
    [ "🐶", false ],
    [ "√", false ],
    [ "#", false ],
    [ "*", false ],
    [ "/", false ],
    [ "_", false ],
    [ "+", false ],
    [ "", false ]
]


for (const test_case of cases) {
    console.assert(isValidName(test_case[0]) == test_case[1], 'Case ' + test_case[0] + ' was not ' + test_case[1])
}
