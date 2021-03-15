function test(someVar, obj) {
  // detect-non-literal-regexp
  r2 = new RegExp(someVar)
  r3 = new RegExp('a' + someVar + 'b')
}
