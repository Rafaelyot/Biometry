import cv2
import numpy as np

from biometric_systems.facial.face import get_features_from_face, Faces

faceCascade = cv2.CascadeClassifier(f'{cv2.data.haarcascades}haarcascade_frontalface_alt2.xml')

DEFAULT_NUMBER_FACES = 7


class Face_biometry:
    def __init__(self, username: str):
        self.username = username

        self.faces = Faces(username=username)

    @staticmethod
    def __take_shoot() -> np.ndarray:
        video_capture = cv2.VideoCapture(0)

        while True:
            # Capture frame-by-frame
            ret, frame = video_capture.read()

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            faces = faceCascade.detectMultiScale(
                gray,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=(60, 60),
                flags=cv2.CASCADE_SCALE_IMAGE
            )

            # Draw a rectangle around the faces
            for (x, y, w, h) in faces:
                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)

            # Display the resulting frame
            cv2.imshow('Video', frame)

            if cv2.waitKey(1) & 0xFF == ord('s'):
                ret, frame = video_capture.read()

                video_capture.release()
                cv2.destroyAllWindows()

                return cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

    def register_new_user(self):
        for i in range(DEFAULT_NUMBER_FACES):
            frame = self.__take_shoot()
            face_features = get_features_from_face(frame=frame)

            self.faces.add(new_face_features=face_features)
        self.faces.save_faces()

    def verify_user(self):
        frame = self.__take_shoot()
        face_features = get_features_from_face(frame=frame)
        print(self.faces.verify_user(face_features))
