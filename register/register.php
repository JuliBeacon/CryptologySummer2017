<?php

//连接数据库
function connect_sql()
{
    $pdo = new PDO('mysql:host=127.0.0.1;dbname=数据库名', '用户名', '密码');
    return $pdo;
}

function insert($sk,$pk){
    if(!isset($_POST['submit'])){
		exit("Wrong!");
  	}

  	$name=$_POST['name'];
  	$email=$_POST['email'];
  	$usr=$_POST['username'];
  	$psw=$_POST['psw'];


    $method="aes-256-cbc";
    $enc_key=bin2hex($psw);
    $enc_options=0;
    $iv_length=openssl_cipher_iv_length($method);
    $iv=openssl_random_pseudo_bytes($iv_length);
    //encrypt user private key and user public key
    $cSK=openssl_encrypt($sk,$method,$enc_key,$enc_options,$iv);
    $cPK=openssl_encrypt($pk,$method,$enc_key,$enc_options,$iv);
    // 定义“私有”的密文结构
    $saved_cSK = sprintf('%s$%d$%s$%s', $method, $enc_options, bin2hex($iv), $cSK);
    $saved_cPK = sprintf('%s$%d$%s$%s', $method, $enc_options, bin2hex($iv), $cPK);


    //密码加盐
    $salt=openssl_random_pseudo_bytes(1024,$cs);
    $saltedPsw=hash("sha256",($psw+$salt));

    //连接数据库
	  $pdo=connect_sql();

    //插入一条新的记录
  	$sql="Insert into user(name,email,username,psw,pubkey,privkey,salt) values (:name,:email,:usr,:saltedPsw,:pk,:sk,:salt)";
  	$pre=$pdo->prepare($sql);
    //$pre->bindparam(':id',$id);
    $pre->bindparam(':name',$name);
    $pre->bindparam(':email',$email);
    $pre->bindparam(':usr',$usr);
    $pre->bindparam(':saltedPsw',$saltedPsw);
    $pre->bindparam(':pk',$saved_cPK);
    $pre->bindparam(':sk',$saved_cSK);
    $pre->bindparam(':salt',$salt);
    $pre->execute();
    //print_r($pre->errorInfo());
	$pdo=null;
}

function genKeys(){
    $config=array(
      "digest_alg"=>"sha256",
      "private_key_bits"=>1024,
      "private_key_type"=>OPENSSL_KEYTYPE_RSA
    );
    $res=openssl_pkey_new($config);
    openssl_pkey_export($res,$privKey);
    $pubKey=openssl_pkey_get_details($res);
    $pubKey=$pubKey["key"];
    $keys=array("SK"=>$privKey,"PK"=>$pubKey);
    return $keys;
}


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

//检查用户名
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


//检查密码强度
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
$nameErr = $emailErr = $usrErr = $pswErr=$pswOK=$pswGreat= $cfmErr="";
$name = $email = $usr = $psw = $cfm="";
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
            $pdo=connect_sql();
            $sql = "SELECT uid FROM user where username='$usr' limit 1"; //该用户名对应ID只能有1个
            if(($pdo->query($sql))->rowcount()>0){
                $usrErr='username already exists';
            }
            else{
                $usrErr=null;
            }
            $pdo=null;
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

    //Confirm password
    $cfm=$_POST["confirm"];
    if($cfm!=$psw){
        $cfmErr="Inconformity!";
    }
    else{
        $cfmErr=null;
    }


	if(!$cfmErr && !$emailErr && empty($usrErr) && empty($pswErr)){
		$mark=TRUE;
	}
	else{
		$mark=false;
	}
}

if($mark){
    $ckeys=genKeys();
    insert($ckeys["SK"],$ckeys["PK"]);
    include("reg_success.html");
}

include ("register.html");
?>
