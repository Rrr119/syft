__declspec(dllimport) const char *syft_10_identity(void);
int main(void) {
    return syft_10_identity()[0] == 's' ? 0 : 1;
}
