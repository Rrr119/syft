extern const char *syft_01_identity(void);
int main(void) {
    return syft_01_identity()[0] == 's' ? 0 : 1;
}
