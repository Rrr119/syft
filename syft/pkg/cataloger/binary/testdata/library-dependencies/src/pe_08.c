__declspec(dllimport) const char *syft_08_identity(void);
int main(void) {
    return syft_08_identity()[0] == 's' ? 0 : 1;
}
