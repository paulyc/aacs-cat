# aacs-cat
decrypt aacs mpeg2 transport stream given volume key or volume id+media key block

for personal use backup purposes only. please do not infringe copyrights. keep artists (and programmers) in business

inspiration: backing up blurays with bad sectors. MakeMKV chokes on it, but ddrescue 
will copy the encrypted mpeg2 transport streams and media key block, and libaacs will
give you the volume ID, from which you can calculate the volume key and decrypt whatever
ddrescue managed to recover.
