__declspec(dllimport) const char *syft_09_identity(void);
int main(void) {
    return syft_09_identity()[0] == 's' ? 0 : 1;
}
