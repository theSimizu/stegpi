#!venv/bin/python
import os
import sys
import argparse
import random
import xxhash
import select
import pathlib
import secrets
import math
import time
import numpy as np
from stegpi.cry import Crypt
from io import BytesIO
from PIL import Image
from hashlib import sha512

sys.dont_write_bytecode = True

parser = argparse.ArgumentParser()

parser.add_argument('action', nargs='?', choices=['embed', 'extract'])
parser.add_argument('-mt', '--method')
parser.add_argument('-if', '--image_file')
parser.add_argument('-mf', '--message_file')
parser.add_argument('-m', '--message')
parser.add_argument('-p', '--password')
parser.add_argument('-o', '--output')

args = parser.parse_args()

class Steganography:
    @staticmethod
    def __text_to_bits(cipher_bytes:bytes):
        return [format(x, 'b').zfill(8) for x in cipher_bytes]
    
    @staticmethod
    def __bits_to_text(binary:list[str]):
        text = ''.join([format(int(txt, 2), 'x').zfill(2) for txt in binary])
        return bytes.fromhex(text)
    
    @staticmethod
    def __recover_bits_with_hamming_code(cover):
        if type(cover) == str or type(cover) == list[str]: cover = [int(x) for x in cover]

        cover = np.array(cover)
        size = int(math.log2(len(cover)+1))

        indexes_with_1 = [[int(c, 2) for c in bin(index+1)[2:].zfill(size)] for index, val in enumerate(cover) if val]
        indexes_with_1.append([0 for _ in range(size)]) # Avoid error if cover is full 0

        transposed_values = np.array(indexes_with_1).transpose()
        xor_current_values = np.array([a.sum()%2 for a in transposed_values])

        return xor_current_values

    @staticmethod
    def __change_bits_with_hamming_code(message, cover):
        if type(message) == str or type(message) == list[str]: message = [int(x) for x in message]
        if type(cover) == str or type(cover) == list[str]: cover = [int(x) for x in cover]
        
        message = np.array(message)
        cover = np.array(cover)

        size = len(message)
        if 2 ** size != len(cover)+1: raise Exception('Incompatible message and cover size')

        indexes_with_1 = [[int(c, 2) for c in bin(index+1)[2:].zfill(size)] for index, val in enumerate(cover) if val]
        indexes_with_1.append([0 for _ in range(size)]) # Avoid error if cover is full 0

        transposed_values = np.array(indexes_with_1).transpose()
        xor_current_values = np.array([a.sum()%2 for a in transposed_values])

        difference = (xor_current_values - message) % 2
        index_to_change = ''.join(difference.astype(str))
        index_to_change = int(index_to_change, 2) -1

        if index_to_change > -1: cover[index_to_change] = not cover[index_to_change]
        return cover
    
    def __init__(self, action='embed', message:str=None, password:str=None, method:str='LSB', image_file:str=None, message_file:str=None, output:str=None) -> None:
        self.__method = method
        self.__message = message
        self.__message_chunk_size = 1
        self.__max_jump = 3
        self.__password = None
        self.__password_hash = None

        # self.__kkk = dict()

        self.__kkk = {
            'png': None,
            'width': None,
            'height': None,
            'pixels_count': None,
            'rgb_count': None,
            'pixels_data': None
        }


        self.set_password(password)
        self.set_image(image_file)
        self.set_output(output)
        if action == 'embed': self.set_message(message, message_file)
        
    def __set_chunk_size(self):
        rgb_used = (self.__kkk['rgb_count']) / (len(self.__binary_message) * 9)
        while rgb_used / 2**self.__message_chunk_size-1 > self.__max_jump and self.__message_chunk_size < 8:
            self.__message_chunk_size += 1
        if self.__message_chunk_size == 1: raise Exception('Message too large')
        self.__cover_size = 2**self.__message_chunk_size-1
        
    def __pixel_jump(self, loop1, loop2):
        salt = str(loop1)+str(loop2)
        jumper = lambda val: int(xxhash.xxh3_64_hexdigest(val)[0:3], 16)
        cur_jump = int(jumper(self.__password_hash+salt)) % self.__max_jump
        if cur_jump == 0: cur_jump = self.__max_jump
        return cur_jump
        
    def __get_zigzag_pixel_coords(self, coords = None):
        if not coords: return (0, 0, False, False)
        x, y, is_NE, is_SW = coords
        w, h = self.__kkk['width']-1, self.__kkk['height']-1

        go_EAST = lambda x, y: (x+1, y, y != 0, y == 0)
        go_SOUTH = lambda x, y: (x, y+1, x==0, x != 0)
        go_NE = lambda x, y: (x+1, y-1, True, False)
        go_SW = lambda x, y: (x-1, y+1, False, True)

        if x == 0 and y == 0: coords = go_EAST(x, y)

        elif x == 0 and not is_NE and y < h: coords = go_SOUTH(x, y)
        elif y == 0 and not is_SW and x < w: coords = go_EAST(x, y)

        elif x == w and not is_SW: coords = go_SOUTH(x, y)
        elif y == h and not is_NE: coords = go_EAST(x, y)

        elif is_NE: coords = go_NE(x, y)
        elif is_SW: coords = go_SW(x, y)

        return coords

    def __zigzag_change_pixels(self):
        def changer(px_value:int, LSB:int):
            if px_value % 2 == LSB: return px_value
            mult = 1 if random.randint(0, 1) else -1
            if px_value >= 255: mult = -1
            if px_value <= 0: mult = 1
            return px_value+mult
        
        def chunked_message():
            EOF = len(self.__binary_message)-1
            nine_bits = lambda chunk, index: f'{chunk}{int(index != EOF)}' # Join 8 bits message (chunk) with a bit to control if is the end of message (index != EOF)
            bin_message = [nine_bits(chunk, index) for index, chunk in enumerate(self.__binary_message)]
            bin_message = ''.join(bin_message)
            bin_message += '0' * (-len(bin_message) % self.__message_chunk_size)
            return [bin_message[x:x+self.__message_chunk_size] for x in range(0, len(bin_message), self.__message_chunk_size)]

        coords = None
        amount_of_pixels_to_hide_data = -(-(2 ** self.__message_chunk_size -1) // 3)
        for chunk_index, chunk in enumerate(chunked_message()):
            altered_pixels_coords = []
            pixels_LSBs_cover = ''

            for loop in range(amount_of_pixels_to_hide_data):
                cur_jump = self.__pixel_jump(chunk_index, loop)
                for loop in range(cur_jump): coords = self.__get_zigzag_pixel_coords(coords)
                x, y = coords[:2]
                altered_pixels_coords.append((x, y))
                LSBs = tuple(str(px_value%2) for px_value in self.__kkk['pixels_data'][x, y])
                pixels_LSBs_cover += ''.join(LSBs)

            altered_LSBs = tuple(Steganography.__change_bits_with_hamming_code(chunk, pixels_LSBs_cover[:self.__cover_size]))
            new_pixels_LSBs = tuple(altered_LSBs[x:x+3] for x in range(0, len(altered_LSBs), 3))

            for index, coord in enumerate(altered_pixels_coords):
                x, y = coord
                pixel_values_pre_change = list(self.__kkk['pixels_data'][x, y])
                new_values_LSB = new_pixels_LSBs[index]
                for i, LSB in enumerate(new_values_LSB): pixel_values_pre_change[i] = changer(pixel_values_pre_change[i], LSB)
                self.__kkk['pixels_data'][x, y] = tuple((255, 0, 0))

    def __get_pixel_with_data_in_zigzag(self, loop1, coords=None):
        try:
            byte_bits = ''
            amount_of_pixels_to_hide_data = -(-(2 ** self.__message_chunk_size -1) // 3)
            for loop2 in range(amount_of_pixels_to_hide_data):
                cur_jump = self.__pixel_jump(loop1, loop2)
                for _ in range(cur_jump): coords = self.__get_zigzag_pixel_coords(coords)
                x, y = coords[:2]
                RGB = list(self.__kkk['pixels_data'][x, y])[:]
                for color in range(3): byte_bits += str(RGB[color] % 2)
            msg = Steganography.__recover_bits_with_hamming_code(byte_bits[:2 ** self.__message_chunk_size -1])
            return (''.join(str(x) for x in msg), coords)
        except:
            raise Exception("Coudn't decrypt")
                
    def set_image(self, path):
        stream = None
        if path:
            raw_image = open(path, 'rb')
            stream = BytesIO(raw_image.read())
            raw_image.close()
        else:
            while select.select([sys.stdin.buffer], [], [], 1)[0]:
                data = sys.stdin.buffer.read()
                if data: stream = BytesIO(data)
                break

        if not stream: raise Exception('Insert an image')
        try:
            self.__kkk['png'] = Image.open(stream).convert('RGB')
            self.__kkk['width'], self.__kkk['height'] = self.__kkk['png'].size
            self.__kkk['pixels_count'] = self.__kkk['width']*self.__kkk['height']
            self.__kkk['rgb_count'] = self.__kkk['pixels_count']*3
            self.__kkk['pixels_data'] = self.__kkk['png'].load()

        except:
            raise Exception('Cannot identify image')

    def set_message(self, message:str|bytes=None, file_path:str=None):
        if type(message) == str: message = message.encode()
        if not message:
            try:
                with open(file_path, 'rb') as msg: message = msg.read()
            except:
                raise Exception('Insert a message or select a file')
        
        self.__message = message

        return self.__message
    
    def set_password(self, password:str):
        if not password: password = 'password'
        self.__password = password
        self.__password_hash = sha512(password.encode()).hexdigest()

    def set_output(self, path:str):
        if path == 'null':
            self.__output = pathlib.Path('/dev/null')
        elif path == '-' or not path:
            self.__output = None
        else:
            out = pathlib.Path(path)
            self.__output = out
            if out.is_dir():
                filename = f'{secrets.token_hex(16)}.png'
                self.__output = pathlib.Path(f'{path}/{filename}').resolve()
            
    def extract_message(self):
        for _ in range(8):
            coords = None
            bits_total_text = ''
            loop = 0
            end_of_message = False
            chunks_of_9_bits = []
            while not end_of_message:
                bits_chunk, coords = self.__get_pixel_with_data_in_zigzag(loop, coords)
                bits_total_text += bits_chunk
                chunks_of_9_bits = [bits_total_text[x:x+9] for x in range(0, len(bits_total_text), 9)]
                loop+=1
                for chunk in chunks_of_9_bits:
                    if not (len(chunk) == 9 and chunk[8] == '0'): continue
                    end_of_message = True
                    break

            while len(chunks_of_9_bits) > 1 and chunks_of_9_bits[-2][-1] == '0': chunks_of_9_bits.pop()
            chunks_of_9_bits = [x[:8] for x in chunks_of_9_bits]

            cipher = Steganography.__bits_to_text(chunks_of_9_bits)
            cry = Crypt(cipher, self.__password.encode())

            extracted_message = cry.gcm_decrypt_message()
            if extracted_message: break
            self.__message_chunk_size+=1


        try:
            if self.__output:
                output = open(self.__output, 'wb')
                output.write(extracted_message)
                output.close()
            else:
                os.write(1, extracted_message)
        except:
            raise Exception('Couldn\'t decrypt')

    def embed_message(self):
        cry = Crypt(self.__message, self.__password)
        if self.__method == 'LSB':
            encrypted_message = cry.gcm_encrypt_message()
            self.__binary_message = Steganography.__text_to_bits(encrypted_message)
            self.__set_chunk_size()
            self.__zigzag_change_pixels()
            img_byte_arr = BytesIO()
            self.__kkk['png'].save(img_byte_arr, format='PNG')
            self.__img_with_secret = img_byte_arr.getvalue()

        if self.__output:
            raw_image = open(self.__output, 'wb')
            raw_image.write(self.__img_with_secret)
            raw_image.close()
        else:
            os.write(1, self.__img_with_secret)

