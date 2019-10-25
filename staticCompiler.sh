gcc ssh-agent.c -o ssh-agent -I. -Ldev/openssl-1.0.2t -Lopenbsd-compat -L. -lssh -lopenbsd-compat -ljwt -lcrypto -ldl -lutil -lz  -lcrypt -lresolv -ljansson
