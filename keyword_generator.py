from json import load, dump
import speech_recognition as sr
from sys import argv


class Configuration(object):
    samples_per_keyword = 5
    top_x = 2

    @staticmethod
    def help():
        print("usage: python3 keyword_generate {arguments}")
        print("\t-h\t--help")
        print("\t-t\t--top-x")
        print("\t-s\t--samples-per-keyword")
        exit()

    @staticmethod
    def parse_arguments(arguments):
        config = Configuration()
        c = 0
        while c < len(arguments):
            a = arguments[c]
            if a in ["-s", "--samples-per-keyword"]:
                config.samples_per_keyword = arguments[c + 1]
            elif a in ["-t", "--top-x"]:
                config.top_x = arguments[c + 1]
            elif a in ["-h", "--help"]:
                Configuration.help()
        return config


class Generator(object):
    @staticmethod
    def generate(config):
        r = sr.Recognizer()
        m = sr.Microphone()

        keywords = load(open("keywords.json"))

        tmp_keywords = {}
        new_keywords = {}

        for key in keywords.keys():
            tmp_keywords[key] = []
            new_keywords[key] = []
            heard_words = 0
            while heard_words < config.samples_per_keyword:
                with m as src:
                    print("%i try; keyword %s" % (heard_words, key))
                    a = r.listen(src)
                try:
                    tmp_keywords[key].append(r.recognize_sphinx(a))
                    heard_words += 1
                except (sr.UnknownValueError, sr.RequestError):
                    pass

        for key in tmp_keywords.keys():
            words = []
            for sentence in tmp_keywords[key]:
                words += sentence.split()
            rank_list = {}
            for word in words:
                if word not in rank_list.keys():
                    rank_list[word] = 1
                else:
                    rank_list[word] += 1
            srtd = sorted(rank_list.items(), key=lambda x: x[1], reverse=True)
            tmp = 0
            while tmp < config.top_x:
                for k, v in srtd:
                    if v is 1:
                        print("all other words only have been heard once")
                        break
                    else:
                        new_keywords[key] += k

        dump(new_keywords, open("new_keywords.json"))
        print("wrote 'new_keywords.json'")


if __name__ == '__main__':
    cfg = Configuration.parse_arguments(argv)
    Generator.generate(cfg)
