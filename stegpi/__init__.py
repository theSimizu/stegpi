from stegpi.steg import Steganography

def run(action='embed', message='', message_file='', password='', image_file='', output=''):
    steg = Steganography(action, message=message, message_file=message_file, password=password, image_file=image_file, output=output)
    if action == 'embed': steg.embed_message()
    elif action == 'extract': steg.extract_message()

# steg.run()