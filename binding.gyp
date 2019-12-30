{
  "targets": [
    {
      "target_name": "addon",
      "sources": [ "./extcrypto/extcrypto.cc" ],
      "include_dirs" : [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
