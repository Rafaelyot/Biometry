from pathlib import Path
import os

import face_recognition
import numpy as np
import pickle


DIRECTORY_SAVE = 'biometric_systems/faces'


def get_features_from_face(frame: np.ndarray, face_locations: list[list]) -> list[float]:
	return face_recognition.face_encodings(frame, known_face_locations=face_locations, model='large')[0]


class Faces:
	def __init__(self, username: str):
		self.username = username

		self.__create_dir_if_not_exist()
		self.__create_user_file_if_not_exist()

		self.pre_defined_faces: list[list[float]] = []
		self.__load_faces()

	def add(self, new_face_features: list[float]):
		self.pre_defined_faces.append(new_face_features)

	def verify_user(self, face_cmp: list[float]) -> bool:
		return face_recognition.compare_faces(self.pre_defined_faces, face_cmp, tolerance=0.4)

	def save_faces(self):
		with open(f"{DIRECTORY_SAVE}/{self.username}", 'wb') as file:
			pickle.dump(self.pre_defined_faces, file)

	def __load_faces(self):
		try:
			with open(f"{DIRECTORY_SAVE}/{self.username}", 'rb') as file:
				self.pre_defined_faces = pickle.load(file)
		except EOFError:
			print('error')
			pass

	def __create_user_file_if_not_exist(self):
		file = Path(f"{DIRECTORY_SAVE}/{self.username}")
		file.touch(exist_ok=True)

	@staticmethod
	def __create_dir_if_not_exist():
		os.makedirs(f"{DIRECTORY_SAVE}/", exist_ok=True)
