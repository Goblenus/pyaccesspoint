import os

def main():
    with open('README.rst', "w") as readme_rst_file:
        try:
            import pypandoc
            long_description = pypandoc.convert('README.md', 'rst')
        except(IOError, ImportError):
            long_description = open('README.md').read()

        readme_rst_file.write(long_description)

    os.remove('README.md')

if __name__ == "__main__":
    main()