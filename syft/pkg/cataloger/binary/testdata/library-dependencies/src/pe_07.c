__declspec(dllimport) const char *syft_07_identity(void);
int main(void) {
    return syft_07_identity()[0] == 's' ? 0 : 1;
}
