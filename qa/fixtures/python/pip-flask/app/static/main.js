
// Unsafe regexp
//var emailExpression = /^([a-zA-Z0-9_.\-])+@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
//var email = "jane@example.com";
//emailExpression.test(email);


// e.g.: var myeval = 'console.log("Hello.");';
function dangerous_eval(myeval) {
  eval(myeval);
}

// e.g.: var myregexpText = "/abcd/";
function dangerous_regexp(myregexpText) {
  var myregexp = new RegExp(myregexpText);
  myregexp.test("abcd");
}

// Bracket object access
var user = function() {
  this.name = 'jon';
  //An empty user constructor.
};

function handler(userInput) {
  var anyVal = 'anyVal';
  user[anyVal] = user[userInput[0]](userInput[1]);
}

function exploit(cmd){
  var userInputStageOne = [
    'constructor',
    'console.log(eval(arguments[0]))'
  ];
  var userInputStageTwo = [
    'anyVal',
    cmd
  ];

  handler(userInputStageOne);
  handler(userInputStageTwo);
}

exploit('console.log("How are you")');

// Timing attack
var userInput = "Jane";
var auth = "Jane";
if (userInput == auth) {
  console.log(userInput);
}



