<!DOCTYPE html>
<html>
<head>
    <title>Email Confirm</title>
</head>
<body style="width:900px;height:500px;margin-right:200px;padding-top:30px;margin-bottom:20px;background-color:#fff;">
    <div class="mailbox" style="width:800px;height:500px;margin-left:200px;padding-top:30px;margin-right:200px;margin-bottom:20px;background-color:#06823a;">
    
        <div class="mainDiv" style="width:600px;height:400px;margin-left:100px;margin-right:100px;margin-bottom:20px;background-color:#fff;border-top-left-radius:8px;border-top-right-radius:8px;border-color:#2f9b4a;">

            <div class="mailheader" style="clear:both;background-color:#ddd;height:50px;border-top-left-radius:8px;border-top-right-radius:8px;border-color:#2f9b4a;">
                <p class="title" style="text-align:center;padding-top:15px;font-weight:800;font-size:18px;color:#055a3d;opacity:1">Email Confirmation</p>
            </div>

            <div class="confirm" style="clear:both;float;left;padding-left:50px;">
                <p style="color:#348b60;font-size:20px;font-weight:700;text-align:center;">Confirm Your Email Address</p>
            </div>

            <div class="mailheader" style="clear:both;float;left">
                <p style="padding-left:50px">Please Confirm that you want to  use this as your profile email address. If you receive this by mistake or were not excepting it please disregard this email.  </p>
            </div>

            <div class="mailheader" style="clear:both;float;left;padding-left:100px;margin-top:40px">
                <div style="text-align: center;">
                    <button type="submit" class="myButton" style="background-color:#00a046;width:400px;height:50px;border-color:#00a046;border-radius:8px;color:white;">
                        <a style="text-decoration: none;color: white" href="{{url('/verifyemail/'.$user->email_token)}}">Confirm your Account</a>
                    </button>
                </div>
            </div>

            <div class="mailheader" style="clear:both;float;left;width:500px;height:300px;margin-left:160px;margin-top:40px;margin-right:200px;margin-bottom:20px">
                <p style="padding-left:20px;text-align:center;">or paste the link to your browser.</p><br>
                
                <p style="text-align: center;">
                    <a href="{{url('/verifyemail/'.$user->email_token)}}" style="color:blue;">{{url('/verifyemail/'.$user->email_token)}}</a>
                </p>
            </div>
        </div>
    </div>
</body>
</html>

