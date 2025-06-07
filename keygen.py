from rsa_keys import generate_key_pair, save_keys

save_keys(*generate_key_pair(), private_file="keys/device_private_key.pem", public_file="keys/device_public_key.pem")

save_keys(*generate_key_pair(), private_file="keys/server_private_key.pem", public_file="keys/server_public_key.pem") 

save_keys(*generate_key_pair(), private_file="keys/ca_private_key.pem", public_file="keys/ca_public_key.pem")