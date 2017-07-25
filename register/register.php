<?php

// Functions to filter user inputs
function filterEmail($field){
    // Sanitize e-mail address
    $field = filter_var(trim($field), FILTER_SANITIZE_EMAIL);
    
    // Validate e-mail address
    if(filter_var($field, FILTER_VALIDATE_EMAIL)){
        return $field;
    }else{
        return FALSE;
    }
}

function filterUsr($field){
    // Sanitize username
    $field = filter_var(trim($field), FILTER_SANITIZE_STRING);
    // Validate username
    if(filter_var($field, FILTER_VALIDATE_REGEXP, array("options"=>array("regexp"=>"/^[\x{4e00}-\x{9fa5}a-zA-Z0-9\s]+$/u")))){
        return $field;
    }else{
        return FALSE;
    }
}

function filterPsw($field){
    $strength=0;    //表示密码强度
    $length = strlen($field);    //密码长度
    /***长度小于7，直接判定为弱口令***/
    if($length<7) return $strength;
    if($length >= 8 && $length <= 15) $strength += 10;   
    if($length >= 16 && $length <=36) $strength += 20;  
    /*** 判断是否全为大写字母或全为小写字母 ***/
    if(strtolower($field) != $field or strtoupper($field) != $field)    $strength += 10;  
	/*** get the numbers in the password ***/    
    preg_match_all('/[0-9]/', $field, $numbers);    
    $strength += count($numbers[0]);   
	/*** check for special chars ***/    
    preg_match_all('[|!@#$%&*//=?,;.:-_+~^]', $field, $specialchars);    
    $strength += sizeof($specialchars[0]);   
	/*** get the number of unique chars ***/    
    $chars = str_split($field);    
    $num_unique_chars = sizeof( array_unique($chars) );    
    $strength += $num_unique_chars * 2;   
	/*** strength is a number 1-10; ***/    
    $strength = $strength > 99 ? 99 : $strength;    
    $strength = floor($strength / 10 + 1);
        
    return $strength;
}


// Define variables and initialize with empty values
$nameErr = $emailErr = $usrErr = $pswErr=$pswOK=$pswGreat="";
$name = $email = $usr = $psw = "";
$mark=false;


if($_SERVER["REQUEST_METHOD"] == "POST"){
	//validate email
    if(empty($_POST["email"])){
        $emailErr = 'Please enter your email.';
    }
    else{
        $email = filterEmail($_POST["email"]);
        if($email == FALSE){
            $emailErr = 'Please enter a valid email.';
        }else{
		$emailErr=null;
	    }
    }
// Validate user name
    if(empty($_POST["username"])){
        $usrErr = 'Please enter your username.';
    }else{
        $usr = filterUsr($_POST["username"]);
        if($usr == FALSE){
            $usrErr = 'Please enter a valid username.';
        }else{
		$usrErr=null;
	    }
    }
//Validate password
    $psw=$_POST["psw"];
    $rank = filterPsw($psw);
    if($rank < 4){
        $pswErr = 'Your password is so weak, please reinput!';
    }
    else{
		$pswErr=null;
        if($rank<8){
            $pswOK="Your password is just-so-so...";
        }
        else{
            $pswGreat="Strong password, Good!";
        }
	}


	if(!$nameErr && !$emailErr && empty($usrErr) && empty($pswErr)){
		$mark=TRUE;
	}
	else{
		$mark=false;
	}
}

if($mark){
	include ("insert.php");
    include("reg_success.html");
}

include ("register.html");
?>