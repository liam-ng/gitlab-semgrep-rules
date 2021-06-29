function test(someVar, obj) {
  // detect-non-literal-regexp
  r1 = new RegExp('boom', 'i')
  r1 = new RegExp('yeah')
  r1 = new RegExp
  r1 = new RegExp()
}
